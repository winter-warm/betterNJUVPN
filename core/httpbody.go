package core

import (
	"bytes"
	"encoding/json"
	"io"
)

// toReader 把任意值序列化为 JSON 请求体。
func toReader(v interface{}) io.Reader {
	data, err := json.Marshal(v)
	if err != nil {
		return bytes.NewReader(nil)
	}
	return bytes.NewReader(data)
}
