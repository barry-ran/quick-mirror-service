//go:build integration && peerloom_release_integration

package control

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/barry-ran/quick-mirror-service/internal/catalog"
	"github.com/barry-ran/quick-mirror-service/internal/identity"
	"github.com/barry-ran/quick-mirror-service/internal/peerloom"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This is SDK-created session admission, not a connected-media test: target
// acceptance stays gated until Bind, and the pending session is then revoked.
// The external driver must use a separately verified official SDK binary.
func TestReleasedSDKControlAdmissionAndDrain(t *testing.T) {
	if os.Getenv("QM_PEERLOOM_RELEASE_TEST_ISOLATED") != "1" {
		t.Skip("isolated released server and SDK fixture required")
	}
	library := os.Getenv("QM_PEERLOOM_RELEASE_SDK_LIBRARY")
	data, err := os.ReadFile(library)
	if err != nil {
		t.Fatal("verified released SDK library required; cannot substitute mock")
	}
	digest := sha256.Sum256(data)
	// Official v0.1.3 Linux artifact SHA256SUMS; tag and build-source commit differ.
	if hex.EncodeToString(digest[:]) != "0792aeadb3f920b68428a7537c9ff7a5cf1478a84ba70102d9053b3987839e8c" {
		t.Fatal("SDK binary is not the pinned official v0.1.3 Linux release")
	}
	driver := filepath.Join(t.TempDir(), "released-sdk-driver.py")
	if err := os.WriteFile(driver, []byte(releasedSDKDriver), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, "python3", driver)
	var diagnostics bytes.Buffer
	cmd.Stderr = &diagnostics
	stdin, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	enc, dec := json.NewEncoder(stdin), json.NewDecoder(stdout)
	t.Cleanup(func() {
		enc.Encode(map[string]string{"action": "stop"})
		stdin.Close()
		if e := cmd.Wait(); e != nil {
			t.Errorf("released SDK driver failed: %v; %s", e, diagnostics.String())
		}
	})
	var peers struct {
		PC       string `json:"pc_device"`
		Phone    string `json:"phone_device"`
		PCApp    string `json:"pc_app"`
		PhoneApp string `json:"phone_app"`
	}
	if e = dec.Decode(&peers); e != nil {
		t.Fatalf("SDK registration/online failed: %v", e)
	}
	tenantID := os.Getenv("QM_PEERLOOM_RELEASE_TEST_TENANT")
	ca, e := os.ReadFile(os.Getenv("QM_PEERLOOM_RELEASE_CA_FILE"))
	if e != nil {
		t.Fatal("fixture CA missing")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid fixture CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	key, e := os.ReadFile(os.Getenv("QM_PEERLOOM_RELEASE_TEST_KEY_FILE"))
	if e != nil {
		t.Fatal("fixture admin key missing")
	}
	adapter, e := peerloom.NewControlClient(peerloom.IdentityConfig{Origin: os.Getenv("QM_PEERLOOM_RELEASE_HTTPS_URL"), TenantID: tenantID, PCApplicationID: peers.PCApp, MobileApplicationID: peers.PhoneApp}, strings.TrimSpace(string(key)), &http.Client{Transport: transport, Timeout: 5 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := pgxpool.ParseConfig(os.Getenv("QM_TEST_DATABASE_URL"))
	if e != nil || !strings.HasSuffix(cfg.ConnConfig.Database, "_test") {
		t.Fatal("isolated test database required")
	}
	admin, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	testID, e := uuid()
	if e != nil {
		t.Fatal(e)
	}
	schema := "qm_released_" + strings.ReplaceAll(testID, "-", "")
	if _, e = admin.Exec(ctx, "CREATE SCHEMA "+schema); e != nil {
		t.Fatal(e)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		pool.Close()
		admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		admin.Close()
	})
	scopeID, e := uuid()
	if e != nil {
		t.Fatal(e)
	}
	directory, e := catalog.NewStore(pool, scopeID, tenantID)
	if e != nil {
		t.Fatal(e)
	}
	if e = directory.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	store, e := NewStore(pool, scopeID, tenantID, peers.PhoneApp, adapter)
	if e != nil {
		t.Fatal(e)
	}
	if e = store.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	owner := identity.Principal{DeviceID: peers.PC, TenantID: tenantID, ApplicationID: peers.PCApp, Role: identity.PC}
	phone := identity.Principal{DeviceID: peers.Phone, TenantID: tenantID, ApplicationID: peers.PhoneApp, Role: identity.Mobile}
	boot, e := uuid()
	if e != nil {
		t.Fatal(e)
	}
	var random [32]byte
	if _, e = rand.Read(random[:]); e != nil {
		t.Fatal(e)
	}
	proof := base64.RawURLEncoding.EncodeToString(random[:])
	if e = directory.EnsureRegistration(ctx, phone); e != nil {
		t.Fatal(e)
	}
	if e = directory.UpdateStatus(ctx, phone, catalog.Status{BootID: boot, Sequence: 1, RuntimeProof: proof}); e != nil {
		t.Fatal(e)
	}
	createKey, _ := uuid()
	intent, _, e := store.Create(ctx, owner, peers.Phone, createKey)
	if e != nil || intent.State != "reserving" || intent.Outcome != "confirmed" {
		t.Fatalf("actual public grant create: %+v %v", intent, e)
	}
	if e = enc.Encode(map[string]string{"action": "connect"}); e != nil {
		t.Fatal(e)
	}
	var incoming struct {
		Session string `json:"session_id"`
		Source  string `json:"source_device_id"`
	}
	if e = dec.Decode(&incoming); e != nil || incoming.Source != peers.PC || incoming.Session == "" {
		t.Fatalf("actual SDK session request: %+v %v", incoming, e)
	}
	bindKey, _ := uuid()
	bound, e := store.Bind(ctx, phone, intent.ID, bindKey, intent.Generation, incoming.Session, boot, proof)
	if e != nil || bound.State != "active" || bound.Session != incoming.Session {
		t.Fatalf("public management session verification/bind: %+v %v", bound, e)
	}
	closeKey, _ := uuid()
	closed, e := store.Close(ctx, owner, intent.ID, closeKey, "user_pc")
	if e != nil || closed.State != "draining" || closed.DrainToken != "" {
		t.Fatalf("actual revoke/PC challenge isolation: %+v %v", closed, e)
	}
	gate, e := store.Get(ctx, phone, intent.ID)
	if e != nil || gate.DrainToken == "" {
		t.Fatalf("authenticated phone challenge missing: %v", e)
	}
	remote, e := adapter.GetSession(ctx, incoming.Session)
	if e != nil || remote.State != "closed" {
		t.Fatalf("released server did not close session after revoke: %+v %v", remote, e)
	}
	// The test host never accepted/opened the pending session's execution gate.
	// This ACK proves this fixture's gate, not a product GPU/input worker lifecycle.
	ackKey, _ := uuid()
	released, e := store.Drained(ctx, phone, intent.ID, ackKey, intent.Generation, incoming.Session, gate.DrainToken, boot, proof)
	if e != nil || released.State != "released" {
		t.Fatalf("authenticated drained ACK: %+v %v", released, e)
	}
	again, _, e := store.Create(ctx, owner, peers.Phone, createKey)
	if e != nil || again.ID != intent.ID || again.State != "released" {
		t.Fatalf("old create command revived: %+v %v", again, e)
	}
	t.Log("real released server + SDK registration/online/request + public grant/session/revoke + business bind/drain passed; no accepted P2P/media/stream claim")
}

// Python standard library host for the pinned public C ABI; no source SDK build.
const releasedSDKDriver = `# Uses only the verified released C ABI; outputs no credentials.
import ctypes as C, json, os, sys, threading, time, uuid, urllib.request
lib=C.CDLL(os.environ['QM_PEERLOOM_RELEASE_SDK_LIBRARY'])
class Event(C.Structure):
 _fields_=[('abi',C.c_uint32),('kind',C.c_uint32),('request',C.c_uint64),('connection',C.c_uint64),('status',C.c_uint32),('size',C.c_uint32),('payload',C.c_void_p),('length',C.c_size_t),('channel',C.c_uint64)]
CB=C.CFUNCTYPE(None,C.c_uint64,C.POINTER(Event));cv=threading.Condition();events=[]
@CB
def callback(who,p):
 e=p.contents;data=C.string_at(e.payload,e.length) if e.length else b''
 with cv:events.append((who,e.kind,e.request,e.connection,e.status,data));cv.notify_all()
lib.dp_sdk_create.argtypes=[C.c_void_p,C.c_size_t,CB,C.c_uint64,C.POINTER(C.c_uint64)];lib.dp_sdk_create.restype=C.c_uint32
lib.dp_sdk_submit.argtypes=[C.c_uint64,C.c_uint32,C.c_uint64,C.c_void_p,C.c_size_t,C.POINTER(C.c_uint64)];lib.dp_sdk_submit.restype=C.c_uint32
lib.dp_sdk_shutdown.argtypes=[C.c_uint64,C.POINTER(C.c_uint64)];lib.dp_sdk_release.argtypes=[C.c_uint64]
def wait(pred,seconds=15):
 end=time.monotonic()+seconds
 with cv:
  while True:
   for i,e in enumerate(events):
    if pred(e):return events.pop(i)
   left=end-time.monotonic()
   if left<=0:raise RuntimeError('released SDK event deadline')
   cv.wait(left)
def submit(sdk,who,op,body=None):
 raw=json.dumps(body).encode() if body is not None else b'';buf=C.create_string_buffer(raw);req=C.c_uint64();status=lib.dp_sdk_submit(sdk,op,0,buf,len(raw),C.byref(req))
 if status:raise RuntimeError('SDK immediate status '+str(status))
 e=wait(lambda e:e[0]==who and e[1]==1 and e[2]==req.value)
 if e[4]:raise RuntimeError('SDK completion status '+str(e[4]))
 return json.loads(e[5]) if e[5] else {}
origin=os.environ['QM_PEERLOOM_RELEASE_TEST_URL'];admin=open(os.environ['QM_PEERLOOM_RELEASE_TEST_KEY_FILE']).read().strip()
def post(path,data):
 req=urllib.request.Request(origin+path,data=json.dumps(data).encode(),headers={'Content-Type':'application/json','Authorization':'Bearer '+admin,'Idempotency-Key':str(uuid.uuid4())})
 with urllib.request.urlopen(req,timeout=5) as r:return json.load(r)
sdks=[]
try:
 info={}
 for who,label,approve in [(1,'pc',False),(2,'phone',True)]:
  app=post('/v1/applications',{'name':'isolated-'+label,'registration_mode':'grant','require_target_approval':approve})
  grant=post('/v1/registration-grants',{'application_id':app['id'],'expires_in_seconds':300})
  raw=json.dumps({'abi_version':1,'origin':origin,'application_id':app['id'],'storage':'memory','development_loopback':True,'auto_reconnect':False}).encode();buf=C.create_string_buffer(raw);sdk=C.c_uint64()
  status=lib.dp_sdk_create(buf,len(raw),callback,who,C.byref(sdk))
  if status:raise RuntimeError('SDK create '+str(status))
  sdks.append(sdk.value)
  dev=submit(sdk.value,who,1,{'registration':{'platform':'linux','installation_public_key':'fixture-'+str(uuid.uuid4()),'registration_grant':grant['grant'],'sdk_version':'release-fixture','metadata':{}},'idempotency_key':str(uuid.uuid4())})
  wait(lambda e:e[0]==who and e[1]==2)
  info[label+'_device']=dev['device_id'];info[label+'_app']=app['id']
 print(json.dumps(info),flush=True)
 for line in sys.stdin:
  cmd=json.loads(line)
  if cmd['action']=='connect':
   submit(sdks[0],1,2,{'target_device_id':info['phone_device']});e=wait(lambda e:e[0]==2 and e[1]==4);incoming=json.loads(e[5]);print(json.dumps({'session_id':incoming['session_id'],'source_device_id':incoming['source_device_id']}),flush=True)
  elif cmd['action']=='stop':break
  else:raise RuntimeError('unsupported driver action')
finally:
 for sdk in sdks:
  req=C.c_uint64();lib.dp_sdk_shutdown(sdk,C.byref(req))
 for sdk in sdks:
  end=time.monotonic()+5
  while lib.dp_sdk_release(sdk)!=0 and time.monotonic()<end:time.sleep(.02)
`
