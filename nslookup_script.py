import subprocess

def nslookup(domain):
    try:
        # Perform nslookup using subprocess and capture the output
        result = subprocess.run(['nslookup', domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout.strip()  # Capture and strip whitespace
        return output
    except Exception as e:
        return f"Error performing nslookup for {domain}: {e}"

def validate_subdomains(file_path):
    valid_subdomains = []
    invalid_subdomains = []

    # Read subdomains from the txt file
    with open(file_path, 'r') as file:
        subdomains = file.readlines()

    # Validate each subdomain using nslookup
    for subdomain in subdomains:
        subdomain = subdomain.strip()  # Remove whitespace or newlines
        if subdomain:  # Check if subdomain is not empty
            output = nslookup(subdomain)
            if "Address:" in output and "can't find" not in output:
                valid_subdomains.append((subdomain, output))  # Append subdomain and its output as a tuple
            else:
                invalid_subdomains.append((subdomain, output))  # Append invalid subdomain and its output

    return valid_subdomains, invalid_subdomains

def format_output_line(subdomain, output):
    # Format a single subdomain result for better readability
    return f"Subdomain: {subdomain}\nNSLookup Output:\n{output}\n\n"

def write_output(valid_subdomains, invalid_subdomains, output_file):
    # Write valid and invalid subdomains with their nslookup outputs to an output file
    with open(output_file, 'w') as file:
        # Write valid subdomains with a header
        file.write("========== Valid Sub-Domains ==========\n")
        file.write(f"{'Subdomain':<30}{'Status':<15}\n")
        file.write(f"{'-'*30}{'-'*15}\n")
        
        for subdomain, output in valid_subdomains:
            file.write(f"{subdomain:<30}VALID\n")
            file.write(f"{output}\n")
            file.write(f"{'-'*50}\n\n")

        # Write a separator
        file.write("\n\n========== Invalid Sub-Domains ==========\n")
        file.write(f"{'Subdomain':<30}{'Status':<15}\n")
        file.write(f"{'-'*30}{'-'*15}\n")
        
        for subdomain, output in invalid_subdomains:
            file.write(f"{subdomain:<30}INVALID\n")
            file.write(f"{output}\n")
            file.write(f"{'-'*50}\n\n")

def main():
    input_file = 'subdomains-omega.txt'  # Using the correct file name
    output_file = 'nslookup_results.txt'  # Output file for nslookup results

    # Validate subdomains and get the list of valid and invalid ones
    valid_subdomains, invalid_subdomains = validate_subdomains(input_file)

    # Write the results to the output file
    write_output(valid_subdomains, invalid_subdomains, output_file)

    print(f"NSLookup results saved to {output_file}")

if __name__ == "__main__":
    main()
