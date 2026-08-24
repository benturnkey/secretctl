package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/tkhq/secretctl/internal/property"
	"github.com/tkhq/secretctl/internal/turnkeyapi"
)

const (
	defaultListLimit = 10
	maxListLimit     = 100
)

type listOptions struct {
	organizationID string
	properties     []string
	limit          int
	format         string
}

type secretOutput struct {
	SecretID         string            `json:"secret_id"`
	Name             *string           `json:"name,omitempty"`
	CreatedAtUnixMs  string            `json:"created_at_unix_ms"`
	StaticProperties map[string]string `json:"static_properties"`
}

func newListCommand(deps dependencies, globalOptions *rootOptions) *cobra.Command {
	options := listOptions{}
	command := &cobra.Command{
		Use:   "list",
		Short: "List secret metadata",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return runList(command, deps, *globalOptions, options)
		},
	}
	flags := command.Flags()
	flags.StringVar(&options.organizationID, "org-id", "", "Turnkey organization ID (or TURNKEY_ORGANIZATION_ID)")
	flags.StringArrayVar(&options.properties, "property", nil, "exact static-property filter in key=value form")
	flags.IntVar(&options.limit, "limit", defaultListLimit, "maximum number of matching secrets")
	flags.StringVar(&options.format, "format", "table", "output format: table or json")
	return command
}

func runList(command *cobra.Command, deps dependencies, globalOptions rootOptions, options listOptions) error {
	organizationID, err := resolveOrganizationID(
		options.organizationID,
		command.Flags().Changed("org-id"),
		deps,
	)
	if err != nil {
		return err
	}
	if options.limit < 1 || options.limit > maxListLimit {
		return payloadError("--limit must be between 1 and 100", errors.New("list limit out of range"))
	}
	if options.format != "table" && options.format != "json" {
		return payloadError("--format must be table or json", errors.New("invalid output format"))
	}
	filters, err := property.Parse(options.properties)
	if err != nil {
		return payloadError("property filters are invalid", err)
	}
	client, err := loadListClient(deps, globalOptions.environment)
	if err != nil {
		return err
	}

	secrets, err := listMatchingSecrets(command.Context(), client, organizationID, filters, options.limit)
	if err != nil {
		return operationError("list", err)
	}
	output, err := makeSecretOutput(secrets)
	if err != nil {
		return operationError("list", err)
	}
	if options.format == "json" {
		encoder := json.NewEncoder(command.OutOrStdout())
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(output); err != nil {
			return wrapAppError(codeInternal, "could not write command output", 1, err)
		}
		return nil
	}
	if err := writeSecretsTable(command.OutOrStdout(), output); err != nil {
		return wrapAppError(codeInternal, "could not write command output", 1, err)
	}
	return nil
}

func listMatchingSecrets(
	ctx context.Context,
	client secretsClient,
	organizationID string,
	filters []turnkeyapi.KeyValue,
	limit int,
) ([]turnkeyapi.SecretMetadata, error) {
	requestLimit := limit
	if len(filters) > 0 {
		requestLimit = maxListLimit
	}
	limitString := strconv.Itoa(requestLimit)
	var after *string
	matches := make([]turnkeyapi.SecretMetadata, 0, limit)

	for {
		response, err := client.ListSecrets(ctx, turnkeyapi.ListSecretsRequest{
			OrganizationID: organizationID,
			PaginationOptions: &turnkeyapi.Pagination{
				After: after,
				Limit: &limitString,
			},
		})
		if err != nil {
			return nil, fmt.Errorf("request secret metadata: %w", err)
		}
		for _, secret := range response.Secrets {
			matched, err := matchesFilters(secret.StaticProperties, filters)
			if err != nil {
				return nil, err
			}
			if matched {
				matches = append(matches, secret)
				if len(matches) == limit {
					return matches, nil
				}
			}
		}
		if len(response.Secrets) < requestLimit || len(filters) == 0 {
			return matches, nil
		}

		cursor := response.Secrets[len(response.Secrets)-1].SecretID
		if cursor == "" {
			return nil, errors.New("turnkey returned an empty pagination cursor")
		}
		if after != nil && *after == cursor {
			return nil, errors.New("turnkey pagination cursor did not advance")
		}
		after = &cursor
	}
}

func matchesFilters(properties, filters []turnkeyapi.KeyValue) (bool, error) {
	propertyMap := make(map[string]string, len(properties))
	for _, item := range properties {
		if _, exists := propertyMap[item.Key]; exists {
			return false, fmt.Errorf("secret metadata contains duplicate static property key %q", item.Key)
		}
		propertyMap[item.Key] = item.Value
	}
	for _, filter := range filters {
		if value, exists := propertyMap[filter.Key]; !exists || value != filter.Value {
			return false, nil
		}
	}
	return true, nil
}

func makeSecretOutput(secrets []turnkeyapi.SecretMetadata) ([]secretOutput, error) {
	output := make([]secretOutput, 0, len(secrets))
	for _, secret := range secrets {
		properties := make(map[string]string, len(secret.StaticProperties))
		for _, item := range secret.StaticProperties {
			if _, exists := properties[item.Key]; exists {
				return nil, fmt.Errorf("secret %s contains duplicate static property key %q", secret.SecretID, item.Key)
			}
			properties[item.Key] = item.Value
		}
		output = append(output, secretOutput{
			SecretID:         secret.SecretID,
			Name:             secret.Name,
			CreatedAtUnixMs:  secret.CreatedAtUnixMs,
			StaticProperties: properties,
		})
	}
	return output, nil
}

func writeSecretsTable(writer io.Writer, secrets []secretOutput) error {
	table := tabwriter.NewWriter(writer, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "SECRET ID\tNAME\tCREATED AT\tSTATIC PROPERTIES"); err != nil {
		return fmt.Errorf("write table header: %w", err)
	}
	for _, secret := range secrets {
		name := "-"
		if secret.Name != nil {
			name = *secret.Name
		}
		createdAtMilliseconds, err := strconv.ParseInt(secret.CreatedAtUnixMs, 10, 64)
		if err != nil {
			return fmt.Errorf("parse creation timestamp for secret %s: %w", secret.SecretID, err)
		}
		createdAt := time.UnixMilli(createdAtMilliseconds).UTC().Format(time.RFC3339)
		if _, err := fmt.Fprintf(
			table,
			"%s\t%s\t%s\t%s\n",
			secret.SecretID,
			name,
			createdAt,
			formatProperties(secret.StaticProperties),
		); err != nil {
			return fmt.Errorf("write secret table row: %w", err)
		}
	}
	if err := table.Flush(); err != nil {
		return fmt.Errorf("flush secret table: %w", err)
	}
	return nil
}

func formatProperties(properties map[string]string) string {
	keys := make([]string, 0, len(properties))
	for key := range properties {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	formatted := make([]string, 0, len(keys))
	for _, key := range keys {
		formatted = append(formatted, key+"="+properties[key])
	}
	return strings.Join(formatted, ",")
}
