import re

def replace_image_tags(file_path):
    # Read the content of the file
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
    
    # Define the regex pattern and the replacement string
    pattern = r'!\[\[Pasted image (\d+)\.png\]\]'
    replacement = r'<img src="/img/Pasted image \1.png" alt="Example Image" width="1080"/>'
    
    # Perform the replacement
    new_content = re.sub(pattern, replacement, content)
    
    # Write the modified content back to the file
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(new_content)
    
    print(f"Image tags replaced successfully in {file_path}")

# Example usage
replace_image_tags('README.md')
