import json
import re
import argparse
from urllib.parse import unquote
import base64
import pandas as pd

# Define regex patterns for PII
PII_PATTERNS = {
    'Email Address': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
    'Phone Number': r'\b(?:\+?1[-.\s]?|0)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
    'Credit Card Number': r'\b(?:\d[ -]*?){13,16}\b',
    'Social Security Number': r'\b\d{3}-\d{2}-\d{4}\b',
    'IP Address': r'\b\d{1,3}(?:\.\d{1,3}){3}\b',
    'Date of Birth': r'\b\d{2}[/-]\d{2}[/-]\d{4}\b',
    # Add more patterns as needed
}

# Define regex patterns for Possible PII
POSSIBLE_PII_PATTERNS = {
    'GUID': r'\b[a-fA-F0-9]{8}\b(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}\b',
    # Add more possible PII patterns
}

def parse_arguments():
    parser = argparse.ArgumentParser(description='Analyze HAR file for PII')
    parser.add_argument('har_file', help='Path to the HAR file')
    parser.add_argument('--include_possible_pii', action='store_true', help='Include possible PII patterns in analysis')
    parser.add_argument('--custom_fields', nargs='*', help='Custom fields to search for, in the format field_name:regex_pattern')
    args = parser.parse_args()
    return {
        'har_file': args.har_file,
        'include_possible_pii': args.include_possible_pii,
        'custom_fields': args.custom_fields,
    }

def process_custom_fields(custom_fields_args):
    custom_fields = {}
    if custom_fields_args:
        for field in custom_fields_args:
            if ':' in field:
                field_name, pattern = field.split(':', 1)
                custom_fields[field_name] = pattern
            else:
                print(f"Invalid custom field format: {field}. Expected format is field_name:regex_pattern")
    return custom_fields

def get_context(line, match_start, match_end, context_chars=30):
    start = max(match_start - context_chars, 0)
    end = min(match_end + context_chars, len(line))
    context = line[start:end]
    if start > 0:
        context = '...' + context
    if end < len(line):
        context = context + '...'
    return context.strip()

def find_pii(text, patterns):
    matches = []
    lines = text.splitlines()
    for line_number, line in enumerate(lines, start=1):
        for pii_type, pattern in patterns.items():
            for match in re.finditer(pattern, line):
                match_text = match.group()
                match_start = match.start()
                match_end = match.end()
                context = get_context(line, match_start, match_end)
                matches.append({
                    'type': pii_type,
                    'match': match_text,
                    'line_number': line_number,
                    'context': context
                })
    return matches

def analyze_entry(idx, entry, pii_patterns, possible_pii_patterns, custom_fields):
    results = []

    request = entry['request']
    response = entry['response']

    url = unquote(request['url'])
    method = request['method']
    request_headers = request.get('headers', [])
    request_postData = request.get('postData', {}).get('text', '')
    response_headers = response.get('headers', [])
    response_content = response.get('content', {}).get('text', '')
    encoding = response.get('content', {}).get('encoding', '')

    # Decode response content if it's base64 encoded
    if encoding == 'base64':
        try:
            response_content = base64.b64decode(response_content).decode('utf-8', errors='replace')
        except Exception as e:
            print(f"Error decoding response content in entry {idx}: {e}")
            response_content = ''

    # Prepare patterns
    patterns = pii_patterns.copy()
    if possible_pii_patterns:
        patterns.update(possible_pii_patterns)
    if custom_fields:
        patterns.update(custom_fields)

    # Analyze URL
    url_matches = find_pii(url, patterns)
    for m in url_matches:
        results.append({
            'Entry': idx,
            'Location': 'URL',
            'Line Number': m['line_number'],
            'Context': m['context'],
            'PII Type': m['type'],
            'Match': m['match'],
        })

    # Analyze request headers
    headers_text = '\n'.join([h.get('name', '') + ': ' + h.get('value', '') for h in request_headers])
    headers_matches = find_pii(headers_text, patterns)
    for m in headers_matches:
        results.append({
            'Entry': idx,
            'Location': 'Request Headers',
            'Line Number': m['line_number'],
            'Context': m['context'],
            'PII Type': m['type'],
            'Match': m['match'],
        })

    # Analyze request postData
    postData_matches = find_pii(request_postData, patterns)
    for m in postData_matches:
        results.append({
            'Entry': idx,
            'Location': 'Request Body',
            'Line Number': m['line_number'],
            'Context': m['context'],
            'PII Type': m['type'],
            'Match': m['match'],
        })

    # Analyze response content
    response_matches = find_pii(response_content, patterns)
    for m in response_matches:
        results.append({
            'Entry': idx,
            'Location': 'Response Body',
            'Line Number': m['line_number'],
            'Context': m['context'],
            'PII Type': m['type'],
            'Match': m['match'],
        })

    return results

def print_results(df):
    if df.empty:
        print("No PII found in the HAR file.")
    else:
        print("PII Findings:")
        print(df.to_string(index=False))

def main(args):
    # Process custom fields
    custom_fields = process_custom_fields(args.get("custom_fields", []))

    # Read HAR file
    with open(args["har_file"], 'r', encoding='utf-8') as f:
        har_data = json.load(f)

    entries = har_data['log']['entries']
    results = []

    # Prepare patterns
    pii_patterns = PII_PATTERNS
    possible_pii_patterns = POSSIBLE_PII_PATTERNS if args["include_possible_pii"] else {}

    for idx, entry in enumerate(entries, 1):
        entry_results = analyze_entry(idx, entry, pii_patterns, possible_pii_patterns, custom_fields)
        results.extend(entry_results)

    # Create a DataFrame from the results
    df = pd.DataFrame(results)

    # Print the results
    print_results(df)

if __name__ == '__main__':
    #args = parse_arguments()
    args = {
        'har_file': "../requests.har",
        'include_possible_pii': False,
        'custom_fields': [],
    }
    main(args)
