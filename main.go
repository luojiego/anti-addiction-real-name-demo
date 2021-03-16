package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"
)

// 请注意 appId, bizId 和 key 均来自调试工具页面
// 若和自己后台展示的不相同，请自行修改
const (
	appId       = "eda3adc56ce84e9baf93c544ad957075"
	bizId       = "1101999999"
	checkUrl    = "https://wlc.nppa.gov.cn/test/authentication/check"
	queryUrl    = "https://wlc.nppa.gov.cn/test/authentication/query"
	loginOutUrl = "https://wlc.nppa.gov.cn/test/collection/loginout"
)

var (
	key = []byte("40c60307a674443b3c4aec35a83b7b50")
)

// 获取 header sign 签名
func getHeader(params url.Values, v interface{}) (url.Values, error) {
	header := url.Values{}
	header.Add("appId", appId)
	header.Add("bizId", bizId)
	// 填充 timestamps
	t := time.Now()
	header.Add("timestamps", strconv.FormatInt(t.UnixNano()/1000000, 10))

	// header.Add("timestamps", strconv.FormatInt(1615878019978, 10))

	// 因为 keys 的长度是固定的，所以此处这样写代码比较合理
	keys := make([]string, 0, len(header)+len(params))
	// header 中的 key
	for k := range header {
		keys = append(keys, k)
	}

	// params 中的 key
	for k := range params {
		keys = append(keys, k)
	}

	// 排序
	sort.Strings(keys)

	var requestBuf bytes.Buffer
	requestBuf.Write(key)
	for _, k := range keys {
		vs, ok := header[k]
		if ok {
			// 避免有 sign 的时候签名了数据
			if k == "sign" {
				continue
			}

			for _, v := range vs {
				requestBuf.WriteString(k)
				requestBuf.WriteString(v)
			}
		} else {
			vs, ok := params[k]
			if ok {
				for _, v := range vs {
					requestBuf.WriteString(k)
					requestBuf.WriteString(v)
				}
			}
		}

	}

	// 如果 body 不为 nil
	if v != nil {
		// json 序列化
		result, err := json.Marshal(v)
		if err != nil {
			return header, err
		}
		requestBuf.Write(result)
	}
	fmt.Printf("加密前: %s\n", requestBuf.String())
	header.Set("sign", fmt.Sprintf("%x", sha256.Sum256(requestBuf.Bytes())))
	return header, nil
}

type RequestInfo struct {
	Ai    string `json:"ai,omitempty"`
	Name  string `json:"name,omitempty"`
	IdNum string `json:"idNum,omitempty"`
}

type RequestBody struct {
	Data string `json:"data,omitempty"`
}

// 上下线上报的项目
type ReportItem struct {
	No int    `json:"no"`           // 批量模式中的索引
	Si string `json:"si"`           // 游戏内部会话标识
	Bt int    `json:"bt"`           // 用户行为类型 0: 下线 1: 上线
	Ot int64  `json:"ot"`           // 行为发生时间戳，秒
	Ct int    `json:"ct"`           // 上报类型 0: 已认证通过类型 2:游客用户
	Di string `json:"di,omitempty"` // 设备标识 由游戏运营单位生成，游客用户下必填
	Pi string `json:"pi,omitempty"` // 已通过实名认证用户的唯一标识，已认证通过用户必填
}

// 上报的数据
type ReportData struct {
	Collections []ReportItem `json:"collections,omitempty"`
}

// 上报上下线返回的数据
type ReportResponse struct {
	ErrCode int                `json:"errcode,omitempty"`
	ErrMsg  string             `json:"errmsg,omitempty"`
	Data    ReportResponseData `json:"data,omitempty"`
}

type ReportResponseData struct {
	Result []ReportResponseData `json:"result,omitempty"`
}

type ResportResultData struct {
	No      int    `json:"no,omitempty"`
	ErrCode int    `json:"errcode,omitempty"`
	ErrMsg  string `json:"errmsg,omitempty"`
}

// check 和 query 返回数据
type ResponseData struct {
	Result ResultData `json:"result,omitempty"`
}

type ResultData struct {
	Status int    `json:"status,omitempty"`
	Pi     string `json:"pi,omitempty"`
}

type Response struct {
	ErrCode int          `json:"err_code,omitempty"`
	ErrMsg  string       `json:"err_msg,omitempty"`
	Data    ResponseData `json:"data,omitempty"`
}

// 测试上报上下线消息
// 若 guest 为 false，则为已实名认证的用户
func ReportLoginout(guest bool, pi string) {
	item := ReportItem{
		No: 0,
		Si: "100086",
		Bt: 1,
		Ot: time.Now().Unix(),
		Pi: pi,
	}
	if guest {
		item.Ct = 2
		item.Di = "klakaljelakjelajkelajkleajke"
	}

	report := ReportData{
		Collections: []ReportItem{item},
	}

	// report := []ReportItem{item}
	fmt.Printf("%v\n", report)

	body, err := getEncryptData(report)
	if err != nil {
		panic(err)
	}

	header, err := getHeader(nil, body)
	if err != nil {
		panic(err)
	}

	res, err := getReportResponse(header, body)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%v\n", res)
}

func getEncryptData(v interface{}) (*RequestBody, error) {
	result, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	fmt.Printf("body: %s\n", string(result))

	result, err = encrypt(result)
	if err != nil {
		return nil, err
	}
	fmt.Printf("encrypt: %x\n", result)
	encode := base64.StdEncoding.EncodeToString(result)
	// fmt.Println("after encode", encode)

	return &RequestBody{
		Data: encode,
	}, nil
}

func check() {
	// 关键参数应该是AES密钥，16或32个字节
	// 选择AES-128或AES-256。
	ai := "100000000000000001"
	info := &RequestInfo{
		Ai:    ai,
		Name:  "某一一",
		IdNum: "110000190101010001",
	}

	body, err := getEncryptData(info)

	header, _ := getHeader(nil, body)

	pi, err := getResponse(header, body)
	if err != nil {
		panic(err)
		// if err == NeedQueryErr {
		// 	query(ai)
		// }
	}
	fmt.Printf("pi: %s\n", pi)
}

func main() {
	check()
	// ai := "100000000000000001"
	// if err := query(ai); err != nil {
	// 	fmt.Printf("query err: %s\n", err)
	// }
	// ReportLoginout(true, "") // 游客模拟
	// ReportLoginout(false, "1fffbjzos82bs9cnyj1dna7d6d29zg4esnh99u") // 已认证用户的模拟
}

func query(ai string) error {
	param := url.Values{}
	// 设置参数
	param.Add("ai", ai)

	header, err := getHeader(param, nil)
	if err != nil {
		return err
	}

	pi, err := getQueryResponse(header, ai)
	if err != nil {
		// if err == NeedQueryErr {
		// 	query(ai)
		// }
		fmt.Printf("err: %s", err)
		return err
	}
	fmt.Printf("pi: %s\n", pi)
	return nil
}

func encrypt(plaintext []byte) ([]byte, error) {
	key, err := hex.DecodeString(string(key))
	if err != nil {
		panic(err)
	}
	// fmt.Printf("key size: %d\n", len(key))
	// fmt.Printf("待ase-128/gcm 加密原文：%s\n", plaintext)
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	fmt.Printf("nonce size: %d\n", gcm.NonceSize())

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

var (
	NeedQueryErr = fmt.Errorf("need query result")
)

func getResponse(urlValue url.Values, v interface{}) (string, error) {
	var req *http.Request
	if v != nil {
		result, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		req, _ = http.NewRequest("POST", checkUrl, bytes.NewBuffer(result))
	} else {
		req, _ = http.NewRequest("POST", checkUrl, nil)
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	for k, v := range urlValue {
		req.Header.Set(k, v[0])
	}
	fmt.Printf("header: %+v\n", req.Header)

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err.Error())
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	responseData := &Response{}
	if err := json.Unmarshal(body, responseData); err != nil {
		return "", err
	}

	if responseData.ErrCode != 0 {
		return "", fmt.Errorf("%d -> %s", responseData.ErrCode, responseData.ErrMsg)
	}

	result := responseData.Data.Result
	if result.Status == 0 {
		return responseData.Data.Result.Pi, nil
	}

	switch result.Status {
	case 0:
		return responseData.Data.Result.Pi, nil
	case 1:
		return "", NeedQueryErr
	case 2:
		return "", fmt.Errorf("")
	}
	return "", fmt.Errorf("result status error: %d", result.Status)
}

func getReportResponse(urlValue url.Values, v interface{}) (*ReportResponse, error) {
	result, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	req, _ := http.NewRequest("POST", loginOutUrl, bytes.NewBuffer(result))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	for k, v := range urlValue {
		req.Header.Set(k, v[0])
	}
	fmt.Printf("header: %+v\n", req.Header)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err.Error())
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	fmt.Printf("%s\n", body)

	responseData := &ReportResponse{}
	if err := json.Unmarshal(body, responseData); err != nil {
		return nil, err
	}

	if responseData.ErrCode != 0 {
		return nil, fmt.Errorf("%d -> %s", responseData.ErrCode, responseData.ErrMsg)
	}
	return responseData, nil
}

func getQueryResponse(urlValue url.Values, ai string) (string, error) {
	u := queryUrl + fmt.Sprintf("?ai=%s", ai)
	req, _ := http.NewRequest("GET", u, nil)
	fmt.Printf("query url: %s\n", u)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	for k, v := range urlValue {
		fmt.Printf("%s -> %s\n", k, v[0])
		req.Header.Set(k, v[0])
	}
	fmt.Printf("header: %+v\n", req.Header)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err.Error())
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	fmt.Printf("%s\n", string(body))

	responseData := &Response{}
	if err := json.Unmarshal(body, responseData); err != nil {
		return "", err
	}

	if responseData.ErrCode != 0 {
		return "", fmt.Errorf("%d -> %s", responseData.ErrCode, responseData.ErrMsg)
	}

	result := responseData.Data.Result
	if result.Status == 0 {
		return responseData.Data.Result.Pi, nil
	}

	switch result.Status {
	case 0:
		return responseData.Data.Result.Pi, nil
	case 1:
		return "", NeedQueryErr
	case 2:
		return "", fmt.Errorf("")
	}
	return "", fmt.Errorf("result status error: %d", result.Status)
}
