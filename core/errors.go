package core

import "errors"

var (
	ErrInvalidPubKey    = errors.New("服务端公钥无效")
	ErrPlaintextTooLong = errors.New("加密明文超过模数长度")
	ErrLoginFailed      = errors.New("登录失败")
	ErrNeedSMS          = errors.New("需要短信/邮箱二次验证")
	ErrSMSPending       = errors.New("短信验证码已发送待校验")
	ErrNeedCaptcha      = errors.New("需要图形验证码")
	ErrSessionExpired   = errors.New("会话已过期")
)
