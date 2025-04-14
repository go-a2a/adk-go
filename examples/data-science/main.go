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
	"sync"

	"github.com/go-a2a/adk-go/pkg/agent"
	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/model"
	"github.com/go-a2a/adk-go/pkg/model/models"
	"github.com/go-a2a/adk-go/pkg/observability"
	"github.com/go-a2a/adk-go/pkg/tool"
)

func main() {
	ctx := context.Background()

	// Initialize observability
	observability.InitLogging("data-science-agent", slog.LevelDebug)
	observability.InitTracing(ctx, "data-science-agent")
	observability.InitMetrics(ctx, "data-science-agent")

	// Set up the model
	model, err := models.NewGoogleModel("gemini-1.5-pro", os.Getenv("GOOGLE_API_KEY"), "")
	if err != nil {
		panic(fmt.Sprintf("Failed to create model: %v", err))
	}

	// Create the multi-agent system
	system := createMultiAgentSystem(model)

	// Start the conversation
	runInteractiveSession(ctx, system)
}

// MultiAgentSystem encapsulates a team of specialized agents
type MultiAgentSystem struct {
	coordinator *agent.Agent
	dataAnalyst *agent.Agent
	statistician *agent.Agent
	visualizer *agent.Agent
	interpreter *agent.Agent
	memory map[string]string
	memoryMutex sync.RWMutex
}

func createMultiAgentSystem(model model.Model) *MultiAgentSystem {
	// Create shared memory for agent communication
	memory := make(map[string]string)

	// Create the Data Analyst agent
	dataAnalyst := agent.NewAgent(
		"data-analyst",
		model,
		getDataAnalystPrompt(),
		"Specialized in data cleaning, preprocessing, and exploratory analysis",
		setupDataAnalystTools(memory),
	)

	// Create the Statistician agent
	statistician := agent.NewAgent(
		"statistician",
		model,
		getStatisticianPrompt(),
		"Specialized in statistical analysis and hypothesis testing",
		setupStatisticianTools(memory),
	)

	// Create the Visualizer agent
	visualizer := agent.NewAgent(
		"visualizer",
		model,
		getVisualizerPrompt(),
		"Specialized in creating data visualizations and charts",
		setupVisualizerTools(memory),
	)

	// Create the Interpreter agent
	interpreter := agent.NewAgent(
		"interpreter",
		model,
		getInterpreterPrompt(),
		"Specialized in interpreting results and providing insights",
		setupInterpreterTools(memory),
	)

	// Create the Coordinator agent with access to all sub-agents
	coordinator := agent.NewAgent(
		"coordinator",
		model,
		getCoordinatorPrompt(),
		"Coordinates the data science team workflow",
		setupCoordinatorTools(memory),
	).WithSubAgents(*dataAnalyst, *statistician, *visualizer, *interpreter)

	return &MultiAgentSystem{
		coordinator:  coordinator,
		dataAnalyst:  dataAnalyst,
		statistician: statistician,
		visualizer:   visualizer,
		interpreter:  interpreter,
		memory:       memory,
		memoryMutex:  sync.RWMutex{},
	}
}

// Agent prompt definitions
func getCoordinatorPrompt() string {
	return `You are the Coordinator of a data science team. Your role is to:
	1. Understand the user's data analysis request
	2. Break down complex data science tasks into subtasks
	3. Delegate tasks to the appropriate specialists on your team
	4. Synthesize results from different team members
	5. Present a cohesive final answer to the user

	Your team consists of:
	- Data Analyst: For data cleaning, preparation, and exploratory analysis
	- Statistician: For statistical analysis, hypothesis testing, and modeling
	- Visualizer: For creating insightful visualizations of the data
	- Interpreter: For explaining results and providing business insights

	When working with the user:
	1. First understand their request thoroughly
	2. Determine which specialists need to be involved
	3. Coordinate the workflow between specialists
	4. Present a comprehensive response that integrates all relevant insights

	You have access to shared memory where you can store and retrieve information
	that needs to be shared between team members. Use this to pass datasets,
	intermediate results, and other information between specialists.`
}

func getDataAnalystPrompt() string {
	return `You are a Data Analyst specialist on a data science team. Your responsibilities include:
	1. Data cleaning and preprocessing
	2. Exploratory data analysis
	3. Feature engineering
	4. Data transformation
	5. Identifying patterns and anomalies

	When given a task:
	1. First load and examine the data structure
	2. Clean the data by handling missing values, outliers, etc.
	3. Perform exploratory analysis to understand distributions and relationships
	4. Prepare the data for further analysis by other team members

	You have access to shared memory to store and retrieve datasets and results.
	Make sure to store your processed datasets and analysis results so they
	can be used by other specialists.`
}

func getStatisticianPrompt() string {
	return `You are a Statistician specialist on a data science team. Your responsibilities include:
	1. Conducting rigorous statistical analysis
	2. Hypothesis testing
	3. Statistical modeling
	4. Correlation and regression analysis
	5. Evaluating statistical significance

	When given a task:
	1. First retrieve the prepared data from shared memory
	2. Apply appropriate statistical methods based on the data and question
	3. Test hypotheses and validate findings
	4. Document your methodology and results

	You have access to shared memory to retrieve datasets and store your results.
	Make sure to store your statistical findings so they can be visualized
	and interpreted by other team members.`
}

func getVisualizerPrompt() string {
	return `You are a Data Visualization specialist on a data science team. Your responsibilities include:
	1. Creating clear and informative visualizations
	2. Choosing appropriate visualization types for different data
	3. Highlighting key patterns and insights visually
	4. Making complex data interpretable through visual means

	When given a task:
	1. First retrieve the relevant data from shared memory
	2. Determine the most effective visualization types for the data
	3. Create visualizations that effectively communicate the insights
	4. Ensure visualizations are properly labeled and easy to interpret

	You have access to shared memory to retrieve datasets and analysis results.
	Store your visualizations in the shared memory so they can be used in the
	final report to the user.`
}

func getInterpreterPrompt() string {
	return `You are an Insights Interpreter on a data science team. Your responsibilities include:
	1. Translating technical findings into business insights
	2. Providing context and meaning to statistical results
	3. Identifying actionable recommendations
	4. Explaining implications in non-technical terms

	When given a task:
	1. First retrieve the analysis results and visualizations from shared memory
	2. Interpret what the findings mean in practical terms
	3. Identify key takeaways and their implications
	4. Formulate clear, actionable recommendations

	You have access to shared memory to retrieve analysis results and visualizations.
	Your interpretations will be used by the Coordinator to present the final
	insights to the user.`
}

// Tool setup functions
func setupCoordinatorTools(memory map[string]string) []tool.Tool {
	registry := tool.NewToolRegistry()

	// Tool to delegate tasks to specialists
	delegateTool := tool.NewBaseTool(
		"delegate_task",
		"Delegate a task to a specialist on the team",
		model.ToolParameterSpec{
			"type":       "object",
			"properties": map[string]any{
				"specialist": map[string]any{
					"type":        "string",
					"description": "The specialist to delegate to (data-analyst, statistician, visualizer, or interpreter)",
					"enum":        []string{"data-analyst", "statistician", "visualizer", "interpreter"},
				},
				"task": map[string]any{
					"type":        "string",
					"description": "The task description for the specialist",
				},
				"context_key": map[string]any{
					"type":        "string",
					"description": "The key in shared memory where context for this task can be found (optional)",
				},
			},
			"required": []string{"specialist", "task"},
		},
		func(ctx context.Context, args json.RawMessage) (string, error) {
			// Parse the arguments
			var params struct {
				Specialist string `json:"specialist"`
				Task       string `json:"task"`
				ContextKey string `json:"context_key,omitempty"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", fmt.Errorf("failed to parse delegation params: %w", err)
			}

			// In a real implementation, this would queue the task for the specialist
			// For this example, we'll simulate the delegation process
			return fmt.Sprintf("Task delegated to %s: '%s'. They will work on this and store results in shared memory.", 
				params.Specialist, params.Task), nil
		},
	)

	// Tool to access shared memory
	memoryTool := createSharedMemoryTool(memory)

	// Register the tools
	registry.Register(delegateTool)
	registry.Register(memoryTool)

	return registry.GetAll()
}

func setupDataAnalystTools(memory map[string]string) []tool.Tool {
	registry := tool.NewToolRegistry()

	// Tool to load and analyze dataset
	dataAnalysisTool := tool.NewBaseTool(
		"analyze_data",
		"Load and analyze a dataset",
		model.ToolParameterSpec{
			"type":       "object",
			"properties": map[string]any{
				"dataset_name": map[string]any{
					"type":        "string",
					"description": "Name or path to the dataset",
				},
				"analysis_type": map[string]any{
					"type":        "string",
					"description": "Type of analysis to perform (summary, cleaning, transformation)",
					"enum":        []string{"summary", "cleaning", "transformation"},
				},
				"output_key": map[string]any{
					"type":        "string",
					"description": "Key to store the results in shared memory",
				},
			},
			"required": []string{"dataset_name", "analysis_type", "output_key"},
		},
		func(ctx context.Context, args json.RawMessage) (string, error) {
			// Parse the arguments
			var params struct {
				DatasetName  string `json:"dataset_name"`
				AnalysisType string `json:"analysis_type"`
				OutputKey    string `json:"output_key"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", fmt.Errorf("failed to parse data analysis params: %w", err)
			}

			// In a real implementation, this would perform actual data analysis
			// For this example, we'll simulate the analysis process
			result := simulateDataAnalysis(params.DatasetName, params.AnalysisType)
			
			// Store the result in shared memory
			memory[params.OutputKey] = result
			
			return fmt.Sprintf("Completed %s analysis on dataset '%s'. Results stored at key '%s'.", 
				params.AnalysisType, params.DatasetName, params.OutputKey), nil
		},
	)

	// Tool to access shared memory
	memoryTool := createSharedMemoryTool(memory)

	// Register the tools
	registry.Register(dataAnalysisTool)
	registry.Register(memoryTool)

	return registry.GetAll()
}

func setupStatisticianTools(memory map[string]string) []tool.Tool {
	registry := tool.NewToolRegistry()

	// Tool to perform statistical analysis
	statsTool := tool.NewBaseTool(
		"statistical_analysis",
		"Perform statistical analysis on processed data",
		model.ToolParameterSpec{
			"type":       "object",
			"properties": map[string]any{
				"data_key": map[string]any{
					"type":        "string",
					"description": "Key to retrieve input data from shared memory",
				},
				"analysis_type": map[string]any{
					"type":        "string",
					"description": "Type of statistical analysis to perform",
					"enum":        []string{"correlation", "regression", "hypothesis_test", "clustering"},
				},
				"parameters": map[string]any{
					"type":        "string",
					"description": "Additional parameters for the analysis as JSON string",
				},
				"output_key": map[string]any{
					"type":        "string",
					"description": "Key to store the results in shared memory",
				},
			},
			"required": []string{"data_key", "analysis_type", "output_key"},
		},
		func(ctx context.Context, args json.RawMessage) (string, error) {
			// Parse the arguments
			var params struct {
				DataKey      string `json:"data_key"`
				AnalysisType string `json:"analysis_type"`
				Parameters   string `json:"parameters,omitempty"`
				OutputKey    string `json:"output_key"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", fmt.Errorf("failed to parse statistical analysis params: %w", err)
			}

			// Check if the input data exists in shared memory
			inputData, exists := memory[params.DataKey]
			if !exists {
				return "", fmt.Errorf("input data not found at key '%s' in shared memory", params.DataKey)
			}

			// In a real implementation, this would perform actual statistical analysis
			// For this example, we'll simulate the analysis process
			result := simulateStatisticalAnalysis(inputData, params.AnalysisType, params.Parameters)
			
			// Store the result in shared memory
			memory[params.OutputKey] = result
			
			return fmt.Sprintf("Completed %s analysis. Results stored at key '%s'.", 
				params.AnalysisType, params.OutputKey), nil
		},
	)

	// Tool to access shared memory
	memoryTool := createSharedMemoryTool(memory)

	// Register the tools
	registry.Register(statsTool)
	registry.Register(memoryTool)

	return registry.GetAll()
}

func setupVisualizerTools(memory map[string]string) []tool.Tool {
	registry := tool.NewToolRegistry()

	// Tool to create visualizations
	visualizeTool := tool.NewBaseTool(
		"create_visualization",
		"Create data visualizations from analysis results",
		model.ToolParameterSpec{
			"type":       "object",
			"properties": map[string]any{
				"data_key": map[string]any{
					"type":        "string",
					"description": "Key to retrieve input data from shared memory",
				},
				"viz_type": map[string]any{
					"type":        "string",
					"description": "Type of visualization to create",
					"enum":        []string{"bar_chart", "line_chart", "scatter_plot", "histogram", "heatmap"},
				},
				"parameters": map[string]any{
					"type":        "string",
					"description": "Additional parameters for the visualization as JSON string",
				},
				"output_key": map[string]any{
					"type":        "string",
					"description": "Key to store the visualization in shared memory",
				},
			},
			"required": []string{"data_key", "viz_type", "output_key"},
		},
		func(ctx context.Context, args json.RawMessage) (string, error) {
			// Parse the arguments
			var params struct {
				DataKey    string `json:"data_key"`
				VizType    string `json:"viz_type"`
				Parameters string `json:"parameters,omitempty"`
				OutputKey  string `json:"output_key"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", fmt.Errorf("failed to parse visualization params: %w", err)
			}

			// Check if the input data exists in shared memory
			inputData, exists := memory[params.DataKey]
			if !exists {
				return "", fmt.Errorf("input data not found at key '%s' in shared memory", params.DataKey)
			}

			// In a real implementation, this would create actual visualizations
			// For this example, we'll simulate the visualization process
			result := simulateVisualization(inputData, params.VizType, params.Parameters)
			
			// Store the result in shared memory
			memory[params.OutputKey] = result
			
			return fmt.Sprintf("Created %s visualization. Result stored at key '%s'.", 
				params.VizType, params.OutputKey), nil
		},
	)

	// Tool to access shared memory
	memoryTool := createSharedMemoryTool(memory)

	// Register the tools
	registry.Register(visualizeTool)
	registry.Register(memoryTool)

	return registry.GetAll()
}

func setupInterpreterTools(memory map[string]string) []tool.Tool {
	registry := tool.NewToolRegistry()

	// Tool to interpret analysis results
	interpretTool := tool.NewBaseTool(
		"interpret_results",
		"Interpret analysis results and provide insights",
		model.ToolParameterSpec{
			"type":       "object",
			"properties": map[string]any{
				"analysis_key": map[string]any{
					"type":        "string",
					"description": "Key to retrieve analysis results from shared memory",
				},
				"visualization_key": map[string]any{
					"type":        "string",
					"description": "Key to retrieve visualization from shared memory (optional)",
				},
				"domain_context": map[string]any{
					"type":        "string",
					"description": "Domain-specific context to consider in interpretation",
				},
				"output_key": map[string]any{
					"type":        "string",
					"description": "Key to store the interpretation in shared memory",
				},
			},
			"required": []string{"analysis_key", "output_key"},
		},
		func(ctx context.Context, args json.RawMessage) (string, error) {
			// Parse the arguments
			var params struct {
				AnalysisKey      string `json:"analysis_key"`
				VisualizationKey string `json:"visualization_key,omitempty"`
				DomainContext   string `json:"domain_context,omitempty"`
				OutputKey        string `json:"output_key"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", fmt.Errorf("failed to parse interpretation params: %w", err)
			}

			// Check if the analysis data exists in shared memory
			analysisData, exists := memory[params.AnalysisKey]
			if !exists {
				return "", fmt.Errorf("analysis data not found at key '%s' in shared memory", params.AnalysisKey)
			}

			// Retrieve visualization if provided
			var vizData string
			if params.VisualizationKey != "" {
				vizData, exists = memory[params.VisualizationKey]
				if !exists {
					return "", fmt.Errorf("visualization not found at key '%s' in shared memory", params.VisualizationKey)
				}
			}

			// In a real implementation, this would provide actual interpretation
			// For this example, we'll simulate the interpretation process
			result := simulateInterpretation(analysisData, vizData, params.DomainContext)
			
			// Store the result in shared memory
			memory[params.OutputKey] = result
			
			return fmt.Sprintf("Completed interpretation of results. Insights stored at key '%s'.", 
				params.OutputKey), nil
		},
	)

	// Tool to access shared memory
	memoryTool := createSharedMemoryTool(memory)

	// Register the tools
	registry.Register(interpretTool)
	registry.Register(memoryTool)

	return registry.GetAll()
}

// Shared memory tool creation function
func createSharedMemoryTool(memory map[string]string) tool.Tool {
	return tool.NewBaseTool(
		"shared_memory",
		"Access the shared memory for storing and retrieving information",
		model.ToolParameterSpec{
			"type":       "object",
			"properties": map[string]any{
				"action": map[string]any{
					"type":        "string",
					"description": "Action to perform (get, put, list)",
					"enum":        []string{"get", "put", "list"},
				},
				"key": map[string]any{
					"type":        "string",
					"description": "Key for the data in shared memory (required for get and put)",
				},
				"value": map[string]any{
					"type":        "string",
					"description": "Value to store (required for put)",
				},
			},
			"required": []string{"action"},
		},
		func(ctx context.Context, args json.RawMessage) (string, error) {
			// Parse the arguments
			var params struct {
				Action string `json:"action"`
				Key    string `json:"key,omitempty"`
				Value  string `json:"value,omitempty"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", fmt.Errorf("failed to parse shared memory params: %w", err)
			}

			switch params.Action {
			case "get":
				if params.Key == "" {
					return "", fmt.Errorf("key is required for 'get' action")
				}
				value, exists := memory[params.Key]
				if !exists {
					return "", fmt.Errorf("key '%s' not found in shared memory", params.Key)
				}
				return value, nil

			case "put":
				if params.Key == "" {
					return "", fmt.Errorf("key is required for 'put' action")
				}
				if params.Value == "" {
					return "", fmt.Errorf("value is required for 'put' action")
				}
				memory[params.Key] = params.Value
				return fmt.Sprintf("Value stored at key '%s'", params.Key), nil

			case "list":
				keys := make([]string, 0, len(memory))
				for k := range memory {
					keys = append(keys, k)
				}
				keysJSON, err := json.MarshalIndent(keys, "", "  ")
				if err != nil {
					return "", fmt.Errorf("failed to marshal keys: %w", err)
				}
				return fmt.Sprintf("Available keys in shared memory:\n%s", string(keysJSON)), nil

			default:
				return "", fmt.Errorf("invalid action '%s', must be one of 'get', 'put', or 'list'", params.Action)
			}
		},
	)
}

// Simulation functions for the tools
func simulateDataAnalysis(datasetName, analysisType string) string {
	switch analysisType {
	case "summary":
		return fmt.Sprintf(`{
  "dataset": "%s",
  "num_records": 1000,
  "num_features": 15,
  "missing_values": {
    "feature1": 23,
    "feature2": 0,
    "feature3": 5
  },
  "data_types": {
    "feature1": "numeric",
    "feature2": "categorical",
    "feature3": "datetime"
  },
  "basic_stats": {
    "feature1": {
      "mean": 42.5,
      "median": 41.0,
      "std": 5.2,
      "min": 30.1,
      "max": 58.7
    }
  }
}`, datasetName)
	case "cleaning":
		return fmt.Sprintf(`{
  "dataset": "%s",
  "cleaning_operations": [
    "removed 23 rows with missing values",
    "normalized numeric features",
    "encoded categorical variables",
    "handled outliers in feature1 and feature4"
  ],
  "clean_dataset_info": {
    "num_records": 977,
    "num_features": 20,
    "data_quality_score": 0.95
  }
}`, datasetName)
	case "transformation":
		return fmt.Sprintf(`{
  "dataset": "%s",
  "transformation_operations": [
    "applied log transformation to feature1",
    "created 5 new engineered features",
    "binned continuous variable feature3 into 5 categories",
    "applied one-hot encoding to categorical variables"
  ],
  "transformed_dataset_info": {
    "num_records": 977,
    "num_features": 28,
    "memory_usage": "45.3 MB"
  }
}`, datasetName)
	default:
		return fmt.Sprintf(`{
  "dataset": "%s",
  "error": "Unknown analysis type: %s"
}`, datasetName, analysisType)
	}
}

func simulateStatisticalAnalysis(inputData, analysisType, parameters string) string {
	switch analysisType {
	case "correlation":
		return `{
  "analysis_type": "correlation",
  "correlation_matrix": {
    "feature1": {
      "feature1": 1.0,
      "feature2": 0.72,
      "feature3": -0.14
    },
    "feature2": {
      "feature1": 0.72,
      "feature2": 1.0,
      "feature3": -0.08
    },
    "feature3": {
      "feature1": -0.14,
      "feature2": -0.08,
      "feature3": 1.0
    }
  },
  "significant_correlations": [
    {
      "variables": ["feature1", "feature2"],
      "correlation": 0.72,
      "p_value": 0.001
    }
  ]
}`
	case "regression":
		return `{
  "analysis_type": "regression",
  "model_type": "linear_regression",
  "target_variable": "feature1",
  "coefficients": {
    "intercept": 12.3,
    "feature2": 3.45,
    "feature3": -0.78,
    "feature4": 2.01
  },
  "model_performance": {
    "r_squared": 0.82,
    "adjusted_r_squared": 0.80,
    "mean_squared_error": 4.56,
    "p_value": 0.001
  },
  "significant_variables": ["feature2", "feature4"]
}`
	case "hypothesis_test":
		return `{
  "analysis_type": "hypothesis_test",
  "test_type": "t_test",
  "null_hypothesis": "There is no difference between groups A and B",
  "alternative_hypothesis": "There is a significant difference between groups A and B",
  "result": {
    "t_statistic": 3.42,
    "p_value": 0.007,
    "degrees_freedom": 28,
    "confidence_interval": [1.2, 6.8]
  },
  "conclusion": "Reject the null hypothesis at the 0.05 significance level. There is a statistically significant difference between groups A and B."
}`
	case "clustering":
		return `{
  "analysis_type": "clustering",
  "algorithm": "k_means",
  "num_clusters": 3,
  "silhouette_score": 0.68,
  "cluster_sizes": [320, 455, 202],
  "cluster_centers": {
    "cluster_1": {
      "feature1": 35.2,
      "feature2": 12.5,
      "feature3": 0.78
    },
    "cluster_2": {
      "feature1": 41.7,
      "feature2": 22.3,
      "feature3": 0.55
    },
    "cluster_3": {
      "feature1": 52.3,
      "feature2": 18.1,
      "feature3": 0.91
    }
  },
  "cluster_interpretations": [
    "Cluster 1 represents low-value customers with high churn risk",
    "Cluster 2 represents mid-value customers with moderate engagement", 
    "Cluster 3 represents high-value customers with strong brand loyalty"
  ]
}`
	default:
		return fmt.Sprintf(`{
  "error": "Unknown analysis type: %s"
}`, analysisType)
	}
}

func simulateVisualization(inputData, vizType, parameters string) string {
	// In a real implementation, this would generate actual visualization data
	// For this example, we'll return a text representation of the visualization
	switch vizType {
	case "bar_chart":
		return `{
  "visualization_type": "bar_chart",
  "title": "Feature Distribution by Category",
  "x_axis": "Category",
  "y_axis": "Value",
  "data": {
    "Category A": 42,
    "Category B": 78,
    "Category C": 53,
    "Category D": 91
  },
  "description": "This bar chart shows the distribution of values across different categories. Category D has the highest value, followed by Category B."
}`
	case "line_chart":
		return `{
  "visualization_type": "line_chart",
  "title": "Trend Analysis Over Time",
  "x_axis": "Month",
  "y_axis": "Value",
  "series": [
    {
      "name": "Series A",
      "data": [42, 45, 51, 53, 56, 61, 63, 58, 54, 52, 49, 45]
    },
    {
      "name": "Series B",
      "data": [30, 32, 35, 41, 43, 45, 48, 46, 42, 38, 35, 33]
    }
  ],
  "description": "This line chart shows two series over a 12-month period. Both series show seasonal patterns with peaks in the middle months."
}`
	case "scatter_plot":
		return `{
  "visualization_type": "scatter_plot",
  "title": "Correlation Between Feature1 and Feature2",
  "x_axis": "Feature1",
  "y_axis": "Feature2",
  "correlation": 0.72,
  "trend_line": {
    "slope": 1.24,
    "intercept": 3.45,
    "r_squared": 0.52
  },
  "description": "This scatter plot shows a strong positive correlation between Feature1 and Feature2. Most data points fall close to the trend line, with a few outliers in the upper right corner."
}`
	case "histogram":
		return `{
  "visualization_type": "histogram",
  "title": "Distribution of Feature1",
  "x_axis": "Value",
  "y_axis": "Frequency",
  "bin_count": 10,
  "bin_range": [30, 60],
  "statistics": {
    "mean": 42.5,
    "median": 41.0,
    "std_dev": 5.2
  },
  "description": "This histogram shows the distribution of Feature1. The distribution appears to be slightly right-skewed with a mean of 42.5 and median of 41.0."
}`
	case "heatmap":
		return `{
  "visualization_type": "heatmap",
  "title": "Correlation Matrix Heatmap",
  "x_axis": "Features",
  "y_axis": "Features",
  "features": ["Feature1", "Feature2", "Feature3", "Feature4"],
  "data": [
    [1.0, 0.72, -0.14, 0.35],
    [0.72, 1.0, -0.08, 0.42],
    [-0.14, -0.08, 1.0, -0.21],
    [0.35, 0.42, -0.21, 1.0]
  ],
  "description": "This heatmap visualizes the correlation matrix between features. Strong positive correlations are shown in darker colors, with Feature1 and Feature2 having the strongest positive correlation (0.72)."
}`
	default:
		return fmt.Sprintf(`{
  "error": "Unknown visualization type: %s"
}`, vizType)
	}
}

func simulateInterpretation(analysisData, vizData, domainContext string) string {
	// In a real implementation, this would provide actual interpretation based on the data
	// For this example, we'll return a simulated interpretation
	return `{
  "interpretation_type": "business_insights",
  "key_findings": [
    "Strong positive correlation (0.72) between customer age and purchase frequency indicates older customers shop more regularly",
    "Analysis revealed three distinct customer segments with different buying patterns and preferences",
    "Statistically significant difference (p=0.007) between marketing campaign A and B effectiveness, with campaign B showing 24% higher conversion rate"
  ],
  "business_implications": [
    "Targeting older demographic segments could increase purchase frequency and customer lifetime value",
    "Personalizing marketing strategies for the three identified segments could improve conversion rates",
    "Shifting marketing budget towards campaign B could improve overall ROI"
  ],
  "recommendations": [
    "Develop targeted promotions for the 55+ age demographic to capitalize on higher purchase frequency",
    "Implement personalized email campaigns for each customer segment based on identified preferences",
    "Increase allocation to campaign B by at least 30% in the next quarter",
    "Further research recommended to understand factors driving higher engagement in cluster 3"
  ],
  "confidence_level": "High",
  "limitations": [
    "Analysis limited to 6 months of data which may not capture longer-term seasonal trends",
    "Customer demographic data was incomplete for approximately 15% of records"
  ]
}`
}

func runInteractiveSession(ctx context.Context, system *MultiAgentSystem) {
	// Print welcome message
	fmt.Println("=== Data Science Multi-Agent System ===")
	fmt.Println("Type 'exit' or 'quit' to end the conversation")
	fmt.Println("How can I help with your data analysis today?")

	// Initialize scanner for user input
	scanner := bufio.NewScanner(os.Stdin)

	// Main conversation loop
	for {
		fmt.Print("\nYou: ")
		if !scanner.Scan() {
			break
		}
		userInput := scanner.Text()

		// Check for exit command
		if strings.EqualFold(userInput, "exit") || strings.EqualFold(userInput, "quit") {
			fmt.Println("\nThank you for using the Data Science Multi-Agent System. Goodbye!")
			break
		}

		// Create a user message
		userMsg := message.NewUserMessage(userInput)

		// Create a context with trace information
		ctxWithSpan, span := observability.StartSpan(ctx, "process_user_input")
		span.SetAttributes(attribute.String("user_input", userInput))
		defer span.End()

		// Process the message with the coordinator agent
		resp, err := system.coordinator.Process(ctxWithSpan, userMsg)
		if err != nil {
			fmt.Printf("\nError: %v\n", err)
			continue
		}

		// Display the response
		fmt.Printf("\nCoordinator: %s\n", resp.Content)
	}
}
