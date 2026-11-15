#!/usr/bin/env python3
"""在全新临时数据库中验证真实QM/Peerloom服务，非SDK、媒体或真机验收。

仅接受本地二进制/源码路径，不接受外部服务URL或现有数据库DSN。
所有秘密临时生成，不打印服务日志；退出时终止子进程、销毁临时目录。
"""
import argparse
import base64
import json
import os
import pathlib
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

PROXY_SOURCE = r'''package main
import("net/http";"net/http/httputil";"net/url";"os";"time")
func main(){u,_:=url.Parse("http://127.0.0.1:"+os.Args[3]);p:=httputil.NewSingleHostReverseProxy(u);s:=&http.Server{Addr:"127.0.0.1:"+os.Args[4],Handler:p,ReadHeaderTimeout:5*time.Second};if err:=s.ListenAndServeTLS(os.Args[1],os.Args[2]);err!=nil{panic(err)}}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--peerloom-root', required=True, type=pathlib.Path, help='已审核源码根目录，读取infra/migrations')
    parser.add_argument('--peerloom-bin', required=True, type=pathlib.Path, help='包含device-server/device-admin/device-migrate的目录')
    parser.add_argument('--qm-bin', required=True, type=pathlib.Path)
    parser.add_argument('--postgres-bin', required=True, type=pathlib.Path)
    parser.add_argument('--redis-bin', required=True, type=pathlib.Path)
    parser.add_argument('--go', default='go', help='Go工具链，仅编译临时透明TLS反代')
    parser.add_argument('--openssl', default='openssl')
    parser.add_argument('--library-path', help='可选隔离工具链动态库路径，不修改系统环境')
    parser.add_argument('--port-base', type=int, default=55800, help='仅占用loopback的连续5端口；冲突即退出')
    args = parser.parse_args()
    if not __debug__:
        parser.error('不得使用python -O关闭测试断言')
    if not 1024 <= args.port_base <= 65530:
        parser.error('port-base必须在1024..65530')
    root=args.peerloom_bin.resolve()
    peer=args.peerloom_root.resolve()
    pg=args.postgres_bin.resolve()
    args.qm_bin=args.qm_bin.resolve()
    # Redis uses argv[0] to select server/tool mode; preserve the executable symlink name.
    args.redis_bin=args.redis_bin.absolute()
    required=[args.qm_bin,args.redis_bin,peer/'infra/migrations',*(root/name for name in ('device-server','device-admin','device-migrate')),*(pg/name for name in ('initdb','pg_ctl','createdb'))]
    if any(not path.exists() for path in required):
        parser.error('缺少所需本地二进制或migration目录')
    pg_port,redis_port,peer_port,tls_port,qm_port=range(args.port_base,args.port_base+5)
    for port in range(args.port_base,args.port_base+5):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1',port))
    processes = []
    with tempfile.TemporaryDirectory(prefix='qm-real-services-') as temp:
        d = pathlib.Path(temp)
        env = os.environ.copy()
        for name in list(env):
            if name.startswith(('QM_', 'DATABASE_URL', 'REPLAY_', 'REDIS_', 'ADMIN_', 'RELAY_', 'WEBHOOK_', 'PG')) or name.lower() in ('http_proxy', 'https_proxy', 'all_proxy'):
                env.pop(name)
        if args.library_path:
            env['LD_LIBRARY_PATH'] = args.library_path
        env.setdefault('GOCACHE', str(d / 'go-cache'))
        env['GOTOOLCHAIN'] = 'local'
        pg_started = False
        proxy_source = d / 'proxy.go'
        proxy_source.write_text(PROXY_SOURCE)
        subprocess.run([args.go, 'build', '-o', str(d / 'tls-proxy'), str(proxy_source)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=120, cwd=d)

        def run(command, **kw):
            result = subprocess.run([str(x) for x in command], env=kw.pop('env', env), capture_output=True, timeout=120, **kw)
            if result.returncode:
                raise RuntimeError(pathlib.Path(command[0]).name + ' failed; command output suppressed to avoid credential disclosure')
            return result

        def start(binary, vars=None, args=()):
            e = env.copy()
            e.update(vars or {})
            log = open(os.devnull, 'wb')
            p = subprocess.Popen([str(binary), *map(str, args)], env=e, stdout=log, stderr=log)
            processes.append((p, log))
            return p

        def stop(p):
            p.terminate()
            try:
                p.wait(timeout=12)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        try:
            run([args.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost', '-keyout', d / 'server.key', '-out', d / 'server.crt'])
            os.chmod(d / 'server.key', 0o600)
            run([pg / 'initdb', '-D', d / 'pgdata', '-A', 'trust', '-U', 'qm_fixture', '--no-locale', '-E', 'UTF8'])
            for name in ['server.key', 'server.crt']:
                shutil.copyfile(d / name, d / 'pgdata' / name)
            os.chmod(d / 'pgdata/server.key', 0o600)
            with open(d / 'pgdata/postgresql.conf', 'a') as f:
                f.write(f"\nlisten_addresses='127.0.0.1'\nport={pg_port}\nunix_socket_directories=''\nssl=on\n")
            run([pg / 'pg_ctl', '-D', d / 'pgdata', '-l', d / 'postgres.log', 'start'])
            pg_started = True
            for db in ['peerloom_test', 'qm_test']:
                run([pg / 'createdb', '-h', '127.0.0.1', '-p', str(pg_port), '-U', 'qm_fixture', db])
            password = uuid.uuid4().hex
            (d / 'redis.password').write_text(password)
            (d / 'replay.key').write_text(base64.b64encode(os.urandom(32)).decode())
            (d / 'redis.conf').write_text(f'bind 127.0.0.1\nport {redis_port}\nrequirepass {password}\nsave ""\nappendonly no\ndir "{d}"\n')
            os.chmod(d / 'redis.conf', 0o600)
            redis = start(args.redis_bin, args=[d / 'redis.conf'])
            peerEnv = {'DATABASE_URL': f'postgres://qm_fixture@127.0.0.1:{pg_port}/peerloom_test?sslmode=verify-full&sslrootcert=' + urllib.parse.quote(str(d / 'server.crt'), safe=''), 'REPLAY_KEY_FILE': str(d / 'replay.key'), 'REDIS_ADDRESS': f'127.0.0.1:{redis_port}', 'REDIS_PASSWORD_FILE': str(d / 'redis.password'), 'LISTEN_ADDRESS': f'127.0.0.1:{peer_port}'}
            pe = env.copy()
            pe.update(peerEnv)
            run([root / 'device-migrate', '--dir', peer / 'infra/migrations', 'up'], env=pe)
            admin = json.loads(run([root / 'device-admin', 'bootstrap', '--offline', '--tenant-name', 'isolated-source-integration', '--scope', 'admin'], env=pe).stdout)
            server = start(root / 'device-server', peerEnv)
            proxy = start(d / 'tls-proxy', args=[d / 'server.crt', d / 'server.key', str(peer_port), str(tls_port)])
            context = ssl.create_default_context(cafile=str(d / 'server.crt'))
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))

            def call(origin, method, path, token=None, body=None, want=200, key=None):
                data = None if body is None else json.dumps(body).encode()
                headers = {'Content-Type': 'application/json', 'Idempotency-Key': key or str(uuid.uuid4())}
                if token:
                    headers['Authorization'] = 'Bearer ' + token
                request = urllib.request.Request(origin + path, data=data, method=method, headers=headers)
                try:
                    r = opener.open(request, timeout=10)
                except urllib.error.HTTPError as e:
                    r = e
                raw = r.read()
                status = r.code
                try:
                    out = json.loads(raw)
                except ValueError:
                    out = {}
                if status != want:
                    raise RuntimeError(f'HTTP assertion failed: method={method}, status={status}, expected={want}; response body suppressed')
                return out
            P = f'https://127.0.0.1:{tls_port}'
            Q = f'https://127.0.0.1:{qm_port}'
            for attempt in range(80):
                try:
                    call(P, 'GET', '/readyz')
                    break
                except Exception as readiness_error:
                    if redis.poll() is not None: raise RuntimeError("Redis exited during startup")
                    if proxy.poll() is not None: raise RuntimeError("TLS proxy exited during startup")
                    if attempt == 79 and isinstance(readiness_error, RuntimeError): raise readiness_error
                    if server.poll() is not None:
                        raise RuntimeError('Peerloom exited during startup')
                    time.sleep(0.1)
            else:
                raise RuntimeError('Peerloom readiness timeout')
            svc = admin['service_credential']
            tenant = admin['tenant_id']
            apps = [call(P, 'POST', '/v1/applications', svc, {'name': name, 'require_target_approval': name == 'Mobile'}, 201)['id'] for name in ['PC', 'Mobile', 'Other']]

            def register(app):
                grant = call(P, 'POST', '/v1/registration-grants', svc, {'application_id': app}, 201)['grant']
                result = call(P, 'POST', '/v1/device-registrations', None, {'application_id': app, 'platform': 'linux', 'installation_tag': uuid.uuid4().hex, 'registration_grant': grant, 'metadata': {'name': 'isolated fixture'}}, 201)
                assert 'expires_at' not in result and len(result['device_credential']) > 40
                return result
            pc, pc2, mobile, mobile2, other = [register(app) for app in [apps[0], apps[0], apps[1], apps[1], apps[2]]]
            scope = str(uuid.uuid4())
            qmEnv = {'QM_DATABASE_URL': f'postgres://qm_fixture@127.0.0.1:{pg_port}/qm_test?sslmode=verify-full&sslrootcert=' + urllib.parse.quote(str(d / 'server.crt'), safe=''), 'QM_PEERLOOM_ORIGIN': P, 'QM_PEERLOOM_SERVICE_CREDENTIAL': svc, 'QM_TENANT_ID': tenant, 'QM_PC_APPLICATION_ID': apps[0], 'QM_MOBILE_APPLICATION_ID': apps[1], 'QM_SERVICE_SCOPE': scope, 'QM_TLS_CERT_FILE': str(d / 'server.crt'), 'QM_TLS_KEY_FILE': str(d / 'server.key'), 'QM_LISTEN_ADDRESS': f'127.0.0.1:{qm_port}', 'SSL_CERT_FILE': str(d / 'server.crt')}
            qe = env.copy()
            qe.update(qmEnv)
            run([args.qm_bin, '-migrate'], env=qe)
            qm = start(args.qm_bin, qmEnv)

            def qmcall(method, path, who, body=None, want=200, key=None):
                return call(Q, method, path, who['device_credential'], body, want, key).get('data')

            def ensure(who):
                return qmcall('POST', '/qm/v1/installations/self/ensure', who, {})
            for attempt in range(80):
                try:
                    pcCode = ensure(pc)
                    break
                except (urllib.error.URLError, ConnectionError):
                    if qm.poll() is not None:
                        raise RuntimeError('QM exited during startup')
                    time.sleep(0.1)
            else:
                raise RuntimeError('QM readiness timeout')
            phoneCode = ensure(mobile)
            ensure(mobile2)
            ensure(pc2)
            assert ensure(pc)['code'] == pcCode['code'] and ensure(mobile)['code'] == phoneCode['code']
            call(Q, 'POST', '/qm/v1/installations/self/ensure', svc, {}, 401)
            qmcall('POST', '/qm/v1/installations/self/ensure', other, {}, 403)
            r1 = qmcall('POST', '/qm/v1/bindings', pc, {'code': phoneCode['code']})
            r2 = qmcall('POST', '/qm/v1/bindings', mobile2, {'code': pcCode['code']})
            assert r1['mobile_id'] == mobile['device_id'] and r2['pc_id'] == pc['device_id']
            page = qmcall('GET', '/qm/v1/bindings', pc)
            assert len(page['items']) == 2 and all((x['peer']['online'] is False for x in page['items']))
            hidden = qmcall('GET', '/qm/v1/binding-code/self', mobile)
            assert hidden['bound'] and 'code' not in hidden
            qmcall('POST', '/qm/v1/binding-code/self/refresh', mobile, {}, 409)
            qmcall('POST', '/qm/v1/bindings', pc2, {'code': phoneCode['code']}, 409)
            unbindKey = str(uuid.uuid4())
            unbound = qmcall('POST', '/qm/v1/bindings/' + r1['binding_id'] + '/unbind', pc, {'expected_revision': r1['revision']}, key=unbindKey)
            assert not unbound['active']
            assert qmcall('GET', '/qm/v1/binding-code/self', mobile)['code'] == phoneCode['code']
            refreshKey = str(uuid.uuid4())
            fresh = qmcall('POST', '/qm/v1/binding-code/self/refresh', mobile, {}, key=refreshKey)
            assert fresh['code'] != phoneCode['code'] and qmcall('POST', '/qm/v1/binding-code/self/refresh', mobile, {}, key=refreshKey)['code'] == fresh['code']
            qmcall('POST', '/qm/v1/bindings', pc, {'code': phoneCode['code']}, 409)
            newBinding = qmcall('POST', '/qm/v1/bindings', pc2, {'code': fresh['code']})
            assert newBinding['binding_id'] != r1['binding_id']
            stop(qm)
            stop(server)
            server = start(root / 'device-server', peerEnv)
            qm = start(args.qm_bin, qmEnv)
            time.sleep(1)
            assert ensure(pc)['code'] == pcCode['code']
            identity = call(P, 'GET', '/v1/device-self', mobile['device_credential'])
            assert identity['device_id'] == mobile['device_id'] and 'credential_expires_at' not in identity
            assert ensure(mobile)['binding']['binding_id'] == newBinding['binding_id']
            call(P, 'POST', '/v1/devices/' + mobile['device_id'] + '/revoke', svc, None, 200)
            qmcall('POST', '/qm/v1/installations/self/ensure', mobile, {}, 401)
            assert ensure(mobile2)['bound']
            detached = qmcall('POST', '/qm/v1/bindings/' + r2['binding_id'] + '/unbind', mobile2, {'expected_revision': r2['revision']})
            assert not detached['active'] and (not ensure(mobile2)['bound'])
            assert qmcall('GET', '/qm/v1/bindings', pc)['items'] == []
            available = qmcall('GET', '/qm/v1/binding-code/self', mobile2)['code']
            batchKey = str(uuid.uuid4())
            batchBody = {'items': [{'client_item_id': 'valid', 'code': available, 'operation_key': batchKey}, {'client_item_id': 'invalid', 'code': 'bad', 'operation_key': str(uuid.uuid4())}]}
            batch = qmcall('POST', '/qm/v1/bindings/batch', pc, batchBody)
            assert batch['items'][0]['binding']['active'] and batch['items'][1]['error']['code'] == 'INVALID_CODE_FORMAT'
            repeated = qmcall('POST', '/qm/v1/bindings/batch', pc, batchBody)
            assert repeated['items'][0]['binding']['binding_id'] == batch['items'][0]['binding']['binding_id']
            stop(server)
            qmcall('GET', '/qm/v1/bindings', pc, want=503)
            print('PASS actual source-built Peerloom + QM + PostgreSQL(TLS) + Redis + transparent TLS proxy')
            print('PASS public registration lifetime/no-expiry; authority role/service-key isolation; idempotent ensure; both binding directions; 1:N and offline presence; bound-code hiding; refresh/idempotency/retired-code; exclusive ownership; both-side unbind/rebind; batch partial/idempotent results; upstream outage denied instead of empty list; process restart persistent identity+relations; public revocation denied by QM')
            print('NOT TESTED formal release SDK/media/PC/Android/real-device; no elapsed-years clock simulation in this run')
        finally:
            for p, log in reversed(processes):
                if p.poll() is None:
                    stop(p)
                log.close()
            if pg_started:
                subprocess.run([str(pg / 'pg_ctl'), '-D', str(d / 'pgdata'), 'stop', '-m', 'fast'], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        main()
    except KeyboardInterrupt:
        print('隔离测试已中断，执行子进程清理。', file=sys.stderr)
        sys.exit(130)
    except (RuntimeError, AssertionError, OSError, subprocess.SubprocessError, KeyError) as error:
        # 不回显子进程参数、API正文或生成的身份/绑定码。
        print('双服务隔离测试失败：'+type(error).__name__+('：'+str(error) if isinstance(error,RuntimeError) else '')+'；未输出凭据或服务响应。', file=sys.stderr)
        sys.exit(1)
