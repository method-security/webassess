// Package cmd implements the CobraCLI commands for the webassess CLI. Subcommands for the CLI should all live within
// this package. Logic should be delegated to internal packages and functions to keep the CLI commands clean and
// focused on CLI I/O.
package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Method-Security/pkg/signal"
	"github.com/Method-Security/pkg/writer"
	"github.com/Method-Security/webassess/internal/config"
	"github.com/Method-Security/webassess/internal/ollama"
	"github.com/palantir/pkg/datetime"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/spf13/cobra"
)

// WebAssess is the main struct for the webassess CLI. It contains both the root command and all subcommands that can be
// invoked during the execution of the CLI. It also is responsible for managing the output configuration as well as the
// output signal itself, which will be written after the execution of the invoked command's Run function.
type WebAssess struct {
	Version      string
	RootFlags    config.RootFlags
	OutputConfig writer.OutputConfig
	OutputSignal signal.Signal
	RootCmd      *cobra.Command
	VersionCmd   *cobra.Command
}

// NewWebAssess creates a new webassess struct with the provided version string. The webassess struct is used throughout the
// subcommands as a contex within which output results and configuration values can be stored.
// We pass the version value in from the main.go file, where we set the version string during the build process.
func NewWebAssess(version string) *WebAssess {
	webassess := WebAssess{
		Version: version,
		RootFlags: config.RootFlags{
			Quiet:       false,
			Verbose:     false,
			OllamaURL:   "http://127.0.0.1:11434",
			OllamaModel: ollama.Model{},
		},
		OutputConfig: writer.NewOutputConfig(nil, writer.NewFormat(writer.SIGNAL)),
		OutputSignal: signal.NewSignal(nil, datetime.DateTime(time.Now()), nil, 0, nil),
	}
	return &webassess
}

// InitRootCommand initializes the root command for the webassess CLI. This command is the parent command for all other
// subcommands that can be invoked. It also sets up the version command, which prints the version of the CLI when invoked.
// The root command also sets up the output configuration and signal, which are used to write the output of the subcommands
// to the appropriate location (file or stdout).
// Here, we set the PersistentPreRunE and PersistentPostRunE functions that are propagated to all subcommands. These functions
// are used to set up the output configuration and signal before the command is run, and to write the output signal after the
// command has completed.
func (a *WebAssess) InitRootCommand() {
	var outputFormat string
	var outputFile string
	a.RootCmd = &cobra.Command{
		Use:   "webassess",
		Short: "Perform an assessment of a security resource with AI at the edge",
		Long:  `Perform an assessment of a security resource with AI at the edge`,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			logger := svc1log.FromContext(cmd.Context())
			// Attempt to get Ollama URL from param, otherwise check that it is locally installed
			// and if it is not locally running, attempt to start ollama
			ollamaURL, err := cmd.Flags().GetString("ollama-url")
			if ollamaURL == "" || err != nil {
				// Check for ollama in the path
				_, pathErr := exec.LookPath("ollama")
				if pathErr != nil {
					a.OutputSignal.AddError(errors.New("ollama is not installed or is not in the system path"))
					return fmt.Errorf("%s", *a.OutputSignal.ErrorMessage)
				}

				// Check to see if ollama is running on the standard URL without being spawned by the CLI
				if !ollama.IsOllamaRunning(ollama.OllamaStandardBaseURL) {
					logger.Info("ollama not running on default port, attempting to start ollama...")
					err := ollama.StartOllama()
					if err != nil {
						a.OutputSignal.AddError(errors.New("failed to start ollama:" + err.Error()))
						return fmt.Errorf("%s", *a.OutputSignal.ErrorMessage)
					}

					// Check to see if ollama is running after attempting to start it
					if !ollama.IsOllamaRunning(ollama.OllamaStandardBaseURL) {
						a.OutputSignal.AddError(errors.New("ollama could not be started by the CLI"))
						return fmt.Errorf("%s", *a.OutputSignal.ErrorMessage)
					}
				}
				ollamaURL = ollama.OllamaStandardBaseURL
			} else {
				// Check to see if ollama is running on the provided URL
				if !ollama.IsOllamaRunning(ollamaURL) {
					a.OutputSignal.AddError(errors.New("ollama is not running on the provided URL"))
					return fmt.Errorf("%s", *a.OutputSignal.ErrorMessage)
				}
			}
			a.RootFlags.OllamaURL = ollamaURL

			// Set OLLAMA_HOST environment variable for ollama client to pick up
			if err := os.Setenv("OLLAMA_HOST", ollamaURL); err != nil {
				a.OutputSignal.AddError(errors.New("failed to set OLLAMA_HOST environment variable: " + err.Error()))
				return fmt.Errorf("%s", *a.OutputSignal.ErrorMessage)
			}

			// Check to see if the target ollama model is available
			allowDownload, err := cmd.Flags().GetBool("allow-download")
			if err != nil {
				a.OutputSignal.AddError(err)
				return fmt.Errorf("%s", *a.OutputSignal.ErrorMessage)
			}
			ollamaModel, err := cmd.Flags().GetString("ollama-model")
			if err != nil {
				a.OutputSignal.AddError(err)
				return fmt.Errorf("%s", *a.OutputSignal.ErrorMessage)
			}

			if !ollama.ModelReady(ollamaURL, ollamaModel) {
				if allowDownload {
					// Download the model only if in allowed list
					if !ollama.IsAllowedModel(ollamaModel) {
						a.OutputSignal.AddError(fmt.Errorf("ollama model '%s' is not in the allowed models list", ollamaModel))
						return fmt.Errorf("%s", *a.OutputSignal.ErrorMessage)
					}
					err := ollama.DownloadOllamaModel(ollamaURL, ollamaModel)
					if err != nil {
						a.OutputSignal.AddError(errors.New("failed to download ollama model: " + err.Error()))
						return fmt.Errorf("%s", *a.OutputSignal.ErrorMessage)
					}
					// Check if model is ready after downloading
					if !ollama.ModelReady(ollamaURL, ollamaModel) {
						a.OutputSignal.AddError(errors.New("ollama model is not ready after download"))
						return fmt.Errorf("%s", *a.OutputSignal.ErrorMessage)
					}
				} else {
					// Exit since model is not available
					a.OutputSignal.AddError(fmt.Errorf("ollama model '%s' is not available and allow-download is not set", ollamaModel))
					return fmt.Errorf("%s", *a.OutputSignal.ErrorMessage)
				}
			}

			// Get model and set it in the root flags
			model, err := ollama.GetModel(ollamaURL, ollamaModel)
			if err != nil {
				a.OutputSignal.AddError(errors.New("failed to get ollama model: " + err.Error()))
				return fmt.Errorf("%s", *a.OutputSignal.ErrorMessage)
			}
			a.RootFlags.OllamaModel = model

			format, err := validateOutputFormat(outputFormat)
			if err != nil {
				return err
			}
			var outputFilePointer *string
			if outputFile != "" {
				outputFilePointer = &outputFile
			} else {
				outputFilePointer = nil
			}
			a.OutputConfig = writer.NewOutputConfig(outputFilePointer, format)
			cmd.SetContext(svc1log.WithLogger(cmd.Context(), config.InitializeLogging(cmd, &a.RootFlags)))
			return nil
		},
		PersistentPostRunE: func(cmd *cobra.Command, _ []string) error {
			completedAt := datetime.DateTime(time.Now())
			a.OutputSignal.CompletedAt = &completedAt
			return writer.Write(
				a.OutputSignal.Content,
				a.OutputConfig,
				a.OutputSignal.StartedAt,
				a.OutputSignal.CompletedAt,
				a.OutputSignal.Status,
				a.OutputSignal.ErrorMessage,
			)
		},
	}

	a.RootCmd.PersistentFlags().BoolVarP(&a.RootFlags.Quiet, "quiet", "q", false, "Suppress output")
	a.RootCmd.PersistentFlags().BoolVarP(&a.RootFlags.Verbose, "verbose", "v", false, "Verbose output")
	a.RootCmd.PersistentFlags().StringP("ollama-url", "u", "", "URL for Ollama service")
	a.RootCmd.PersistentFlags().StringP("ollama-model", "m", "qwen2.5:0.5b", "Ollama model and version to use for assessment")
	a.RootCmd.PersistentFlags().BoolP("allow-download", "d", false, "Allow downloading of models from internet if not already available")
	a.RootCmd.PersistentFlags().StringVarP(&outputFile, "output-file", "f", "", "Path to output file. If blank, will output to STDOUT")
	a.RootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "signal", "Output format (signal, json, yaml). Default value is signal")

	a.VersionCmd = &cobra.Command{
		Use:   "version",
		Short: "Prints the version number of webassess",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println(a.Version)
		},
		PersistentPostRunE: func(cmd *cobra.Command, _ []string) error {
			return nil
		},
	}
	a.RootCmd.AddCommand(a.VersionCmd)
}

func validateOutputFormat(output string) (writer.Format, error) {
	var format writer.FormatValue
	switch strings.ToLower(output) {
	case "json":
		format = writer.JSON
	case "yaml":
		format = writer.YAML
	case "signal":
		format = writer.SIGNAL
	default:
		return writer.Format{}, errors.New("invalid output format. Valid formats are: json, yaml, signal")
	}
	return writer.NewFormat(format), nil
}
