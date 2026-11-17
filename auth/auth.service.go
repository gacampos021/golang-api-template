package auth

import (
	"net/http"
	"log"
	"study-api/mongo"

	"go.mongodb.org/mongo-driver/bson"
	"github.com/gin-gonic/gin"
)

type LoginRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	Token string `json:"token"`
	User  string `json:"user"`
}

func Login(c *gin.Context) {
	var req LoginRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "email e password são obrigatórios",
		})
		return
	}

	var user bson.M
	err := mongo.MongoClient.Database("users").Collection("users").
		FindOne(c, bson.M{"email": req.Email}).Decode(&user)
	if err != nil {
		log.Printf("erro ao buscar usuário: %v", err)
		return
	}

	log.Printf("%+v", user)

	if req.Email != user["email"] || req.Password != user["password"] {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "email ou senha incorretos",
		})
		return
	}

	token, err := GenerateToken(user["user"].(string), req.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, LoginResponse{
		Token: token,
		User:  req.Email,
	})
}
