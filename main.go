package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	_ "ecommerce/docs"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title E-ticaret odev API
// @version 1.0
// @description This is a sample e-commerce server.
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8080
// @BasePath /

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization

var (
	db *gorm.DB
)

type User struct {
	ID        int64      `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `gorm:"index" json:"deleted_at,omitempty"`
	Username  string     `gorm:"unique" json:"username"`
	Password  string     `json:"password"`
	Role      string     `json:"role"`
	Orders    []Order    `json:"orders"`
}

type Product struct {
	ID          int64      `gorm:"primaryKey" json:"id"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `gorm:"index" json:"deleted_at,omitempty"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Price       float64    `json:"price"`
}

type Order struct {
	ID        int64      `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `gorm:"index" json:"deleted_at,omitempty"`
	UserID    int64      `json:"user_id"`
	ProductID int64      `json:"product_id"`
	Quantity  int        `json:"quantity"`
	Product   Product    `json:"product"`
}

func startDB() {
	var err error
	dbconnect := "host=postgres user=postgres password=postgres dbname=ecommerce_db port=5432 sslmode=disable"
	db, err = gorm.Open(postgres.Open(dbconnect), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	db.AutoMigrate(&User{}, &Product{}, &Order{})
}

// @Summary Register a new user
// @Description Register a new user with a username and password
// @Accept json
// @Produce json
// @Param user body User true "User Info"
// @Success 200 {object} User
// @Router /register [post]
func registerUser(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	user.Role = "user"
	db.Create(&user)
	c.JSON(http.StatusOK, user)
}

// @Summary Login a user
// @Description Login a user and return a JWT token
// @Accept json
// @Produce json
// @Param user body User true "User Info"
// @Success 200 {object} map[string]string
// @Router /login [post]
func loginUser(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var dbUser User
	db.Where("username = ? AND password = ?", user.Username, user.Password).First(&dbUser)
	if dbUser.ID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid login details"})
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID": dbUser.ID,
		"role":   dbUser.Role,
		"exp":    time.Now().Add(time.Hour * 72).Unix(),
	})
	tokenString, _ := token.SignedString([]byte("secret"))
	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func authMiddleware(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid auth"})
		c.Abort()
		return
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		c.Abort()
		return
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		c.Set("userID", int64(claims["userID"].(float64)))
		c.Set("role", claims["role"])
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		c.Abort()
		return
	}
	c.Next()
}

func adminControl(c *gin.Context) {
	role := c.GetString("role")
	if role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "you are not authorized"})
		c.Abort()
		return
	}
	c.Next()
}

// @Summary Create a new product
// @Description Create a new product (Admin only)
// @Accept json
// @Produce json
// @Param product body Product true "Product Info"
// @Success 200 {object} Product
// @Router /products [post]
// @Security ApiKeyAuth
func createProduct(c *gin.Context) {
	var product Product
	if err := c.ShouldBindJSON(&product); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	db.Create(&product)
	c.JSON(http.StatusOK, product)
}

// @Summary Update a product
// @Description Update a product (Admin only)
// @Accept json
// @Produce json
// @Param id path int64 true "Product ID"
// @Param product body Product true "Product Info"
// @Success 200 {object} Product
// @Router /products/{id} [put]
// @Security ApiKeyAuth
func updateProduct(c *gin.Context) {
	var product Product
	id := c.Param("id")
	if err := db.First(&product, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "product not found"})
		return
	}
	if err := c.ShouldBindJSON(&product); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	db.Save(&product)
	c.JSON(http.StatusOK, product)
}

// @Summary Delete a product
// @Description Delete a product (Admin only)
// @Param id path int64 true "Product ID"
// @Success 200 {string} string "ok"
// @Router /products/{id} [delete]
// @Security ApiKeyAuth
func deleteProduct(c *gin.Context) {
	var product Product
	id := c.Param("id")
	if err := db.Delete(&product, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

// @Summary Get user orders
// @Description Get all orders for the logged-in user
// @Produce json
// @Success 200 {array} Order
// @Router /orders [get]
// @Security ApiKeyAuth
func getOrders(c *gin.Context) {
	userID := c.GetInt64("userID")
	var orders []Order
	db.Where("user_id = ?", userID).Preload("Product").Find(&orders)
	c.JSON(http.StatusOK, orders)
}

// @Summary Create an order
// @Description Create a new order for the logged-in user
// @Accept json
// @Produce json
// @Param order body Order true "Order Info"
// @Success 200 {object} Order
// @Router /orders [post]
// @Security ApiKeyAuth
func createOrder(c *gin.Context) {
	userID := c.GetInt64("userID")
	var order Order
	if err := c.ShouldBindJSON(&order); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	order.UserID = userID
	db.Create(&order)
	c.JSON(http.StatusOK, order)
}

func main() {
	startDB()

	r := gin.Default()

	r.POST("/register", registerUser)
	r.POST("/login", loginUser)

	authorized := r.Group("/")
	authorized.Use(authMiddleware)
	{
		admin := authorized.Group("/")
		admin.Use(adminControl)
		{
			authorized.POST("/products", adminControl, createProduct)
			authorized.PUT("/products/:id", adminControl, updateProduct)
			authorized.DELETE("/products/:id", adminControl, deleteProduct)
		}

		authorized.GET("/orders", getOrders)
		authorized.POST("/orders", createOrder)
	}

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	r.Run(":8080")
}
