package core

import (
	"fmt"
	"net/url"
)

// GetMaskedPhone 查询绑定手机号的掩码形式（短信弹窗展示用）。
// 对应门户 /passport/v1/public/phoneNumber?authId=...，data.phoneNumber[0] 形如 159****3515。
func (s *Session) GetMaskedPhone(authId string) string {
	q := url.QueryEscape(authId)
	url := fmt.Sprintf("%s/passport/v1/public/phoneNumber?%s&authId=%s", portalBase, clientParams, q)
	var env struct {
		Code int `json:"code"`
		Data struct {
			PhoneNumber []string `json:"phoneNumber"`
		} `json:"data"`
	}
	if err := s.GetJSON(url, &env); err != nil || env.Code != 0 {
		return ""
	}
	if len(env.Data.PhoneNumber) == 0 {
		return ""
	}
	return env.Data.PhoneNumber[0]
}
