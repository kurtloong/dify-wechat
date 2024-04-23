package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
)

// XMLMessage 用于解析来自企业微信的 XML 数据
type XMLMessage struct {
	XMLName      xml.Name `xml:"xml"`
	ToUserName   string   `xml:"ToUserName"`
	FromUserName string   `xml:"FromUserName"`
	CreateTime   int64    `xml:"CreateTime"`
	MsgType      string   `xml:"MsgType"`
	Content      string   `xml:"Content"`
	MsgId        int64    `xml:"MsgId"`
}

const (
	WxWorkAgentID    = "123"
	WxWorkCorpID     = "123"
	WxWorkCorpSecret = "123"
	WxWorkToken      = "123"
	WxWorkAesKey     = "123"
	DIFY_APPTOKEN    = "123"
)

// Cache 对象，用于存储 token 和 conversation ID
var baseCache = cache.New(5*time.Minute, 10*time.Minute)

// generateTokenKey 生成用于缓存的 access token 的键
func generateTokenKey() string {
	agentID := WxWorkAgentID
	return fmt.Sprintf("%s:access-token", agentID)
}

// generateConversationKey 生成对话键
func generateConversationKey(userName string) string {
	agentID := WxWorkAgentID
	return fmt.Sprintf("%s:%s", agentID, userName)
}

// getToken 从微信 API 获取或缓存中读取 access token
func getToken() (string, error) {
	key := generateTokenKey()
	if token, found := baseCache.Get(key); found {
		return token.(string), nil
	}

	// 从微信 API 获取新的 token
	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://qyapi.weixin.qq.com/cgi-bin/gettoken", nil)
	if err != nil {
		return "", err
	}
	q := req.URL.Query()
	q.Add("corpid", WxWorkCorpID)
	q.Add("corpsecret", WxWorkCorpSecret)
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var res struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", err
	}

	// 将新的 token 存入缓存
	expiration := time.Duration(res.ExpiresIn) * time.Second
	baseCache.Set(key, res.AccessToken, expiration)

	return res.AccessToken, nil
}

// sendWxMessage 向用户发送消息
func sendWxMessage(message, user string) {
	token, err := getToken()
	if err != nil {
		log.Printf("Error getting token: %v", err)
		return
	}

	msgData := map[string]interface{}{
		"touser":                   user,
		"msgtype":                  "text",
		"agentid":                  WxWorkAgentID,
		"text":                     map[string]string{"content": message},
		"safe":                     0,
		"enable_id_trans":          0,
		"enable_duplicate_check":   0,
		"duplicate_check_interval": 1800,
	}

	data, err := json.Marshal(msgData)
	if err != nil {
		log.Printf("Error marshalling message data: %v", err)
		return
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", "https://qyapi.weixin.qq.com/cgi-bin/message/send", bytes.NewBuffer(data))
	if err != nil {
		log.Printf("Error creating request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.URL.RawQuery = "access_token=" + token

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending message: %v", err)
		return
	}
	defer resp.Body.Close()

	var res map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		log.Printf("Error decoding response: %v", err)
		return
	}

	log.Printf("Message sent: %v", res)
}

func sendDifyMessage( message, userName string) {
	conversationKey := generateConversationKey(userName)
	conversationID, found := baseCache.Get(conversationKey)
	if !found {
		conversationID = ""
	}

	client := &http.Client{}
	reqBody := map[string]interface{}{
		"inputs":          map[string]string{},
		"response_mode":   "blocking",
		"query":           message,
		"user":            userName,
		"conversation_id": conversationID,
	}

	data, err := json.Marshal(reqBody)

	log.Printf("Request data: %s", data)
	if err != nil {
		log.Printf("Error marshalling request data: %v", err)
		return
	}

	req, err := http.NewRequest("POST", "http://127.0.0.1/v1/chat-messages", bytes.NewBuffer(data))
	if err != nil {
		log.Printf("Error creating request: %v", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+DIFY_APPTOKEN)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending request to Dify: %v", err)
		return
	}
	defer resp.Body.Close()

	var res map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		log.Printf("Error decoding response from Dify: %v", err)
		return
	}

	log.Printf("Dify response: %v", res)
	newConversationID := res["conversation_id"].(string)
	if newConversationID != "" && newConversationID != conversationID {
		baseCache.Set(conversationKey, newConversationID,time.Hour)
	}

	responseText := res["answer"].(string)
	sendWxMessage( responseText, userName)
}

// asyncSendMessage 处理异步发送消息的逻辑
func asyncSendMessage(xmlData string) {
	var msg XMLMessage
	err := xml.Unmarshal([]byte(xmlData), &msg)
	if err != nil {
		log.Printf("Error unmarshalling XML: %v", err)
		return
	}

	if msg.MsgType != "text" {
		log.Printf("Unsupported message type: %s", msg.MsgType)
		return
	}

	userName := msg.FromUserName
	message := msg.Content

	switch message {
	case "/new":
		// Reset conversation ID
		baseCache.Set(generateConversationKey(userName),nil,time.Hour)
		sendWxMessage("新建成功，开始新的对话吧~~", userName)
	default:
		sendWxMessage( "AI 思考中~~", userName)
		sendDifyMessage(message, userName)
	}
}

// verifySignature 验证消息的签名是否正确
func verifySignature(token, timestamp, nonce, encryptedMsg, signature string) bool {
	// 这里需要实现实际的签名验证逻辑
	// 通常是将 token、timestamp、nonce 和消息内容进行某种形式的排序组合，然后进行哈希计算
	// 返回计算的签名与提供的签名是否相同
	return true // 假设验证总是通过，实际应用中应替换为正确的逻辑
}

func main() {
	token := WxWorkToken
	encodingAeskey := WxWorkAesKey
	corpid := WxWorkCorpID

	wxcpt := NewWXBizMsgCrypt(token, encodingAeskey, corpid, XmlType)
	router := gin.Default()
	router.GET("/", func(c *gin.Context) {
		msgSignature := c.Query("msg_signature")
		timestamp := c.Query("timestamp")
		nonce := c.Query("nonce")
		echoStr := c.Query("echostr")
		log.Printf("Received query params - msg_signature: %s, timestamp: %s, nonce: %s", msgSignature, timestamp, nonce)
		log.Printf("Received echo string: %s", echoStr)

		// 验证签名
		echoStrRes, cryptErr := wxcpt.VerifyURL(msgSignature, timestamp, nonce, echoStr)
		if cryptErr != nil {
			log.Printf("Decrypt error: %v", cryptErr)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt message"})
			return
		}
		msgStr := string(echoStrRes)
		log.Printf("Decrypted message: %s", msgStr)

		c.String(http.StatusOK, msgStr)
	})

	router.POST("/", func(c *gin.Context) {
		log.Printf("Received message")

		msgSignature := c.Query("msg_signature")
		timestamp := c.Query("timestamp")
		nonce := c.Query("nonce")

		// 直接读取请求体
		body, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			log.Printf("Error reading body: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read request body"})
			return
		}

		message, cryptErr := wxcpt.DecryptMsg(msgSignature, timestamp, nonce, body)
		if cryptErr != nil {
			log.Printf("Decrypt error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt message"})
			return
		}
		go func() {
			asyncSendMessage( string(message))
		}()
		c.JSON(http.StatusOK, gin.H{"message": "Received message"})
	})

	router.Run(":9098")
}
