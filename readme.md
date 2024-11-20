# PII Analyzer for HAR Files (Beta)

## Description

The **PII Analyzer for HAR Files** is a Python script designed to scan HTTP Archive (HAR) files for **Personally Identifiable Information (PII)**. It inspects all HTTP requests and responses within the HAR file, analyzing URLs, headers, request bodies, and response bodies to detect PII using predefined and custom regex patterns.

This tool is particularly useful for developers, security analysts, and privacy officers who need to ensure that sensitive data is not inadvertently exposed in network communications.

## Features

- **Detection of Common PII**: Uses predefined regex patterns to detect common PII types such as email addresses, phone numbers, credit card numbers, social security numbers, IP addresses, and dates of birth.
- **Possible PII Patterns**: Optionally includes patterns for possible PII like GUIDs (Globally Unique Identifiers).
- **Custom Fields Support**: Allows users to define custom regex patterns to search for specific fields or data within the HAR file.
- **Contextual Reporting**: Provides line numbers and context snippets where PII is detected to facilitate easier analysis.
- **Structured Output**: Collects results in a structured format suitable for creating Pandas DataFrames, allowing for easy data manipulation and export.
- **Configurable Analysis**: Users can enable or disable possible PII patterns and custom fields via command-line arguments.

## Disclaimer

**This is a beta script**. It is provided as-is and may contain bugs or limitations. It is intended for testing and evaluation purposes. Use it cautiously and do not rely on it as the sole means of detecting PII in your data.

## Why Use This Script?

- **Data Privacy Compliance**: Helps organizations comply with data protection regulations by identifying PII that may be exposed in network communications.
- **Security Auditing**: Assists security professionals in auditing web applications for inadvertent leakage of sensitive information.
- **Development Testing**: Enables developers to test their applications to ensure that PII is not being transmitted unintentionally.
- **Customization**: Offers flexibility through custom regex patterns to detect organization-specific identifiers or data.

## Prerequisites

- **Python 3.x**: Ensure you have Python 3 installed on your system.
- **Required Python Packages**:
- `pandas`
- **Standard Libraries Used**: `json`, `re`, `argparse`, `urllib.parse`, `base64`

## Installation

1. **Download the Script**

Save the `main.py` script to your local machine.

2. **Install Required Packages**

Install the required Python packages using `pip`:

```bash
pip install pandas
```

## Usage

The script is run from the command line and requires the path to a HAR file as input.

### Basic Command

```bash
python main.py path_to_your_file.har
```

### Options

- **Include Possible PII Patterns**

To include patterns for possible PII (e.g., GUIDs):

```bash
python main.py path_to_your_file.har --include_possible_pii
```

- **Include Custom Fields**

To include custom fields with your own regex patterns:

```bash
python main.py path_to_your_file.har --custom_fields "field_name:regex_pattern"
```

You can specify multiple custom fields:

```bash
python main.py path_to_your_file.har --custom_fields "userID:\buserID:\s*(\w+)\b" "token:\btoken:\s*([^\s]+)\b"
```

### Examples

- **Including Both Possible PII and Custom Fields**

```bash
python main.py path_to_your_file.har --include_possible_pii --custom_fields "myId:\bmyId:\s*(\w+)\b"
```

- **Analyzing Without Additional Patterns**

```bash
python main.py path_to_your_file.har
```

## Output

The script analyzes each entry in the HAR file and outputs a table containing:

- **Entry**: The entry number in the HAR file.
- **Location**: Where the PII was found (e.g., URL, Request Headers).
- **Line Number**: The line number within the text where the PII was found.
- **Context**: A snippet of text surrounding the PII match.
- **PII Type**: The type/category of PII detected.
- **Match**: The specific matched text.

**Example Output**:

```
PII Findings:
Entry        Location  Line Number                                             Context           PII Type             Match
 1              URL            1  ...contact us at support@example.com for more...  Email Address  support@example.com
 2  Request Headers            3  ...Authorization: Bearer abcdef12345token...            Token       abcdef12345token
```

## Notes

- **Customizable Context Length**: The context snippet length can be adjusted by modifying the `context_chars` parameter in the `get_context` function within the script.
- **Extensibility**: You can add more patterns to the `PII_PATTERNS` and `POSSIBLE_PII_PATTERNS` dictionaries in the script to detect additional types of PII.
- **Data Handling**: The results are stored in a Pandas DataFrame, which can be exported to CSV or other formats for further analysis.

To save the results to a CSV file, you can modify the script to include:

```python
df.to_csv('pii_findings.csv', index=False)
```

- **Error Handling**: The script includes basic error handling for decoding issues and invalid custom field formats.

## Limitations

- **Beta Version**: As a beta script, it may not cover all edge cases or detect all possible PII. Testing and validation are recommended before using it in production environments.
- **Regex Limitations**: The accuracy of PII detection depends on the regex patterns used. False positives or negatives may occur.
- **Performance**: Processing very large HAR files may be slow. Optimization or batch processing might be necessary for large datasets.

## Privacy and Compliance

- **Handle with Care**: HAR files and the output may contain sensitive information. Ensure that you handle all data in compliance with relevant data protection laws and organizational policies.
- **Authorization**: Always ensure you have proper authorization to analyze the data contained in the HAR files.

## Contributing

Contributions are welcome! If you find bugs or have suggestions for improvements, please feel free to submit an issue or pull request.

## License

This project is licensed under the **MIT License**.

---

By using this script, you acknowledge that it is provided "as-is" without any warranties and that you are responsible for ensuring compliance with all applicable laws and regulations.

---

**Note**: Always exercise caution when handling PII and ensure that you are compliant with all relevant data protection regulations such as GDPR, HIPAA, or CCPA.