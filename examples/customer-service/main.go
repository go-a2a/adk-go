// Copyright 2025 The adk-go Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/go-a2a/adk-go/pkg/agent"
	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/model"
	"github.com/go-a2a/adk-go/pkg/model/models"
	"github.com/go-a2a/adk-go/pkg/observability"
	"github.com/go-a2a/adk-go/pkg/tool"
	"github.com/go-a2a/adk-go/pkg/utils/ptr"
)

func main() {
	ctx := context.Background()

	// Initialize observability
	observability.InitLogging("customer-service-agent", slog.LevelDebug)
	observability.InitTracing(ctx, "customer-service-agent")
	observability.InitMetrics(ctx, "customer-service-agent")

	// Set up the model
	googleModel, err := models.NewGoogleModel("gemini-1.5-pro", os.Getenv("GOOGLE_API_KEY"), "")
	if err != nil {
		panic(fmt.Sprintf("Failed to create model: %v", err))
	}

	// Create the tools
	tools := setupTools()

	// Create the agent
	agent := agent.NewAgent(
		"customer-service",
		googleModel,
		getSystemPrompt(),
		"A customer service agent for Cymbal Home & Garden",
		tools,
	)

	// Start the conversation
	runInteractiveSession(ctx, agent)
}

func getSystemPrompt() string {
	return `You are a helpful customer service agent for Cymbal Home & Garden, 
	a store specializing in home improvement, gardening, and outdoor living products.
	Your role is to assist customers with product information, order inquiries, 
	and general assistance. Be friendly, professional, and helpful.

	You have access to tools that can help you with various customer service tasks. 
	Use these tools when needed to provide accurate information.
	Always maintain a friendly demeanor and aim to resolve customer issues effectively.

	When a customer asks about products, orders, or requests assistance, 
	identify their needs and use the appropriate tools to help them.`
}

func setupTools() []tool.Tool {
	// Create a registry for the tools
	registry := tool.NewToolRegistry()

	// Add product search tool
	productSearchTool := tool.NewBaseTool(
		"product_search",
		"Search for products in the store's inventory",
		model.ToolParameterSpec{
			"type": "object",
			"properties": map[string]any{
				"query": map[string]any{
					"type":        "string",
					"description": "The search query for products",
				},
				"category": map[string]any{
					"type":        "string",
					"description": "Optional product category to filter by",
				},
			},
			"required": []string{"query"},
		},
		func(ctx context.Context, args json.RawMessage) (string, error) {
			// Parse the arguments
			var params struct {
				Query    string `json:"query"`
				Category string `json:"category,omitempty"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", fmt.Errorf("failed to parse product search params: %w", err)
			}

			// Mock product search functionality
			products := mockProductSearch(params.Query, params.Category)
			productJSON, err := json.MarshalIndent(products, "", "  ")
			if err != nil {
				return "", fmt.Errorf("failed to marshal product results: %w", err)
			}

			return string(productJSON), nil
		},
	)

	// Add order lookup tool
	orderLookupTool := tool.NewBaseTool(
		"order_lookup",
		"Look up details of a customer order",
		model.ToolParameterSpec{
			"type": "object",
			"properties": map[string]any{
				"order_id": map[string]any{
					"type":        "string",
					"description": "The ID of the order to look up",
				},
				"email": map[string]any{
					"type":        "string",
					"description": "The customer's email address for verification",
				},
			},
			"required": []string{"order_id"},
		},
		func(ctx context.Context, args json.RawMessage) (string, error) {
			// Parse the arguments
			var params struct {
				OrderID string `json:"order_id"`
				Email   string `json:"email,omitempty"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", fmt.Errorf("failed to parse order lookup params: %w", err)
			}

			// Mock order lookup functionality
			order := mockOrderLookup(params.OrderID)
			orderJSON, err := json.MarshalIndent(order, "", "  ")
			if err != nil {
				return "", fmt.Errorf("failed to marshal order results: %w", err)
			}

			return string(orderJSON), nil
		},
	)

	// Add appointment scheduling tool
	appointmentTool := tool.NewBaseTool(
		"schedule_appointment",
		"Schedule a consultation or service appointment",
		model.ToolParameterSpec{
			"type": "object",
			"properties": map[string]any{
				"service_type": map[string]any{
					"type":        "string",
					"description": "Type of service or consultation needed",
				},
				"preferred_date": map[string]any{
					"type":        "string",
					"description": "Preferred date (YYYY-MM-DD format)",
				},
				"preferred_time": map[string]any{
					"type":        "string",
					"description": "Preferred time of day (morning, afternoon, evening)",
				},
				"customer_name": map[string]any{
					"type":        "string",
					"description": "Customer's name",
				},
				"contact_info": map[string]any{
					"type":        "string",
					"description": "Customer's contact information (email or phone)",
				},
			},
			"required": []string{"service_type", "preferred_date", "customer_name", "contact_info"},
		},
		func(ctx context.Context, args json.RawMessage) (string, error) {
			// Parse the arguments
			var params struct {
				ServiceType   string `json:"service_type"`
				PreferredDate string `json:"preferred_date"`
				PreferredTime string `json:"preferred_time,omitempty"`
				CustomerName  string `json:"customer_name"`
				ContactInfo   string `json:"contact_info"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", fmt.Errorf("failed to parse appointment params: %w", err)
			}

			// Mock appointment scheduling functionality
			appointment := mockScheduleAppointment(params.ServiceType, params.PreferredDate,
				params.PreferredTime, params.CustomerName, params.ContactInfo)

			return fmt.Sprintf("Appointment scheduled successfully.\n\nConfirmation Number: %s\n\nDetails:\n- Service: %s\n- Date: %s\n- Time: %s\n- Name: %s\n- Contact: %s",
				appointment.ConfirmationNumber,
				appointment.ServiceType,
				appointment.Date,
				appointment.Time,
				appointment.CustomerName,
				appointment.ContactInfo), nil
		},
	)

	// Register the tools
	registry.Register(productSearchTool)
	registry.Register(orderLookupTool)
	registry.Register(appointmentTool)

	return registry.GetAll()
}

// Product represents a store product
type Product struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Category    string  `json:"category"`
	Price       float64 `json:"price"`
	InStock     bool    `json:"in_stock"`
	Rating      float64 `json:"rating,omitempty"`
}

// Order represents a customer order
type Order struct {
	OrderID      string        `json:"order_id"`
	CustomerName string        `json:"customer_name"`
	OrderDate    string        `json:"order_date"`
	Status       string        `json:"status"`
	Items        []OrderItem   `json:"items"`
	Total        float64       `json:"total"`
	Shipping     *ShippingInfo `json:"shipping,omitempty"`
}

// OrderItem represents an item in an order
type OrderItem struct {
	ProductID   string  `json:"product_id"`
	ProductName string  `json:"product_name"`
	Quantity    int     `json:"quantity"`
	Price       float64 `json:"price"`
}

// ShippingInfo represents shipping information for an order
type ShippingInfo struct {
	Carrier           string `json:"carrier"`
	TrackingNumber    string `json:"tracking_number,omitempty"`
	EstimatedDelivery string `json:"estimated_delivery,omitempty"`
	ShippedDate       string `json:"shipped_date,omitempty"`
}

// Appointment represents a customer service appointment
type Appointment struct {
	ConfirmationNumber string `json:"confirmation_number"`
	ServiceType        string `json:"service_type"`
	Date               string `json:"date"`
	Time               string `json:"time"`
	CustomerName       string `json:"customer_name"`
	ContactInfo        string `json:"contact_info"`
}

// Mock functions to simulate backend services
func mockProductSearch(query, category string) []Product {
	// Sample product database
	products := []Product{
		{
			ID:          "P12345",
			Name:        "Deluxe Garden Hose",
			Description: "50ft expandable garden hose with 8 spray patterns",
			Category:    "Garden",
			Price:       29.99,
			InStock:     true,
			Rating:      4.5,
		},
		{
			ID:          "P23456",
			Name:        "Premium Potting Soil",
			Description: "25L organic potting soil for indoor and outdoor plants",
			Category:    "Garden",
			Price:       12.99,
			InStock:     true,
			Rating:      4.8,
		},
		{
			ID:          "P34567",
			Name:        "LED Patio Lights",
			Description: "String of 50 LED lights for outdoor use, solar powered",
			Category:    "Outdoor Living",
			Price:       34.99,
			InStock:     true,
			Rating:      4.2,
		},
		{
			ID:          "P45678",
			Name:        "Ceramic Flower Pot Set",
			Description: "Set of 3 decorative ceramic flower pots in various sizes",
			Category:    "Home Decor",
			Price:       24.99,
			InStock:     true,
			Rating:      4.0,
		},
		{
			ID:          "P56789",
			Name:        "Pruning Shears",
			Description: "Professional grade garden pruning shears with ergonomic handles",
			Category:    "Garden Tools",
			Price:       18.99,
			InStock:     true,
			Rating:      4.7,
		},
	}

	// Filter by search query
	var results []Product
	for _, p := range products {
		if strings.Contains(strings.ToLower(p.Name), strings.ToLower(query)) ||
			strings.Contains(strings.ToLower(p.Description), strings.ToLower(query)) {

			// Filter by category if provided
			if category == "" || strings.EqualFold(p.Category, category) {
				results = append(results, p)
			}
		}
	}

	return results
}

func mockOrderLookup(orderID string) Order {
	// For demonstration, return a predefined order for any ID
	// In a real application, this would look up the order in a database
	return Order{
		OrderID:      orderID,
		CustomerName: "Jane Smith",
		OrderDate:    "2025-03-15",
		Status:       "Shipped",
		Items: []OrderItem{
			{
				ProductID:   "P12345",
				ProductName: "Deluxe Garden Hose",
				Quantity:    1,
				Price:       29.99,
			},
			{
				ProductID:   "P45678",
				ProductName: "Ceramic Flower Pot Set",
				Quantity:    1,
				Price:       24.99,
			},
		},
		Total: 54.98,
		Shipping: &ShippingInfo{
			Carrier:           "FastShip",
			TrackingNumber:    "FS3845729",
			EstimatedDelivery: "2025-03-20",
			ShippedDate:       "2025-03-16",
		},
	}
}

func mockScheduleAppointment(serviceType, date, time, name, contact string) Appointment {
	// In a real application, this would check availability and create an appointment
	// For demonstration, it always succeeds
	if time == "" {
		time = "Morning (9:00-12:00)"
	}

	return Appointment{
		ConfirmationNumber: fmt.Sprintf("APPT-%d", os.Getpid()),
		ServiceType:        serviceType,
		Date:               date,
		Time:               time,
		CustomerName:       name,
		ContactInfo:        contact,
	}
}

func runInteractiveSession(ctx context.Context, agent *agent.Agent) {
	// Print welcome message
	fmt.Println("=== Cymbal Home & Garden Customer Service ===")
	fmt.Println("Type 'exit' or 'quit' to end the conversation")
	fmt.Println("How can I help you today?")

	// Initialize scanner for user input
	scanner := bufio.NewScanner(os.Stdin)

	// Start the conversation history with a system message
	history := []message.Message{
		message.NewSystemMessage(getSystemPrompt()),
	}

	// Main conversation loop
	for {
		fmt.Print("\nYou: ")
		if !scanner.Scan() {
			break
		}
		userInput := scanner.Text()

		// Check for exit command
		if strings.EqualFold(userInput, "exit") || strings.EqualFold(userInput, "quit") {
			fmt.Println("\nThank you for using Cymbal Home & Garden Customer Service. Have a great day!")
			break
		}

		// Add user message to history
		userMsg := message.NewUserMessage(userInput)
		history = append(history, userMsg)

		// Create a context with trace information
		ctxWithSpan, span := observability.StartSpan(ctx, "process_user_input")
		span.SetAttributes(attribute.String("user_input", userInput))
		defer span.End()

		// Process the message
		resp, err := agent.Process(ctxWithSpan, userMsg)
		if err != nil {
			fmt.Printf("\nError: %v\n", err)
			continue
		}

		// Add response to history
		history = append(history, resp)

		// Display the response
		fmt.Printf("\nAgent: %s\n", resp.Content)
	}
}
