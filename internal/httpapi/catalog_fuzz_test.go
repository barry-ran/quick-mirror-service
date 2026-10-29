package httpapi

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"unicode/utf8"
)

// 自定义重复键/深度/节点预算扫描器接受时，必须保留标准 JSON 的值语义。
func FuzzStrictObjectDecoder(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{}`),
		[]byte(`{"uuids":["bad","11111111-1111-4111-8111-111111111111"]}`),
		[]byte(`{"permissions":{"projection":true,"projection":false}}`),
		[]byte(`{"text":"中文\u0000","nested":[{"value":null},false,1.5]}`),
		[]byte(`{"value":1e9999}`),
		[]byte(`{} {}`),
		{'{', '"', 0xff, '"', ':', '0', '}'},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return // 与 HTTP 正文边界相同，不测试无界分配。
		}
		var got map[string]any
		if decodeStrictObject(bytes.NewReader(data), &got) != nil {
			return
		}
		if !utf8.Valid(data) || !json.Valid(data) {
			t.Fatal("accepted invalid UTF-8 or JSON")
		}
		var standard map[string]any
		if json.Unmarshal(data, &standard) != nil || !reflect.DeepEqual(got, standard) {
			t.Fatal("strict scanner changed JSON semantics")
		}
	})
}
