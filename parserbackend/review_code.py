import json
import sys
import threading
from colorama import init, Fore, Style
import time
from athena_client import prompt_athena

init()  # Initialize colorama

def loading_animation():
    """Show loading animation like a terminal loading bar"""
    #shapes = ["◴", "◷", "◶", "◵"]
    shapes = ["🕐", "🕑", "🕒", "🕓", "🕔", "🕕", "🕖", "🕗", "🕘", "🕙", "🕚", "🕛"]
    colors = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.BLUE, Fore.MAGENTA, Fore.CYAN]
    i = 0
    while loading_animation.running:
        color = colors[i % len(colors)]
        shape = shapes[i % len(shapes)]
        sys.stdout.write('\r' + f">> analyzing code {color}{shape} {Style.RESET_ALL}")
        sys.stdout.flush()
        i += 1
        time.sleep(0.3)
    sys.stdout.write('\r' + ' ' * 50 + '\r')
    sys.stdout.flush()

class CodeReviewer:
    def analyze_vulnerability(self, file_info: dict, component: str, confidence: str) -> dict:
        """
        Analyze if a component is present in the code
        
        Args:
            file_info (dict): Dictionary containing file path and count
            component (str): Component to search for
            confidence (str): Initial confidence level
            
        Returns:
            dict: Analysis results containing component presence and details
        """
        # Read the file content
        file_path = file_info['file']
        try:
            with open(file_path, 'r') as f:
                file_content = f.read()
        except Exception as e:
            return {
                "component_found": False,
                "direct_usage": False,
                "usage_details": f"Could not read file: {str(e)}"
            }

        prompt = f"""
You are a code analyzer. Analyze this code to determine if the specified component is present and how it's being used.

Context:
- Component to find: {component}
- Initial confidence: {confidence} (indicates the likelihood of finding this component)
- File path: {file_path}
- Usage count hint: {file_info['count']}

Code Content:
{file_content}

Task:
1. Search for the component '{component}' in the code:
   - Check for direct imports
   - Check for usage in code

Format your response as JSON:
{{
    "component_found": false,
    "direct_usage": false,
    "usage_details": "Component not found in the code"
}}
"""
        # Start animation
        loading_animation.running = True
        animation_thread = threading.Thread(target=loading_animation)
        animation_thread.start()

        try:
            # Get analysis from CodeLlama
            response = prompt_athena(prompt)
            
            # Stop animation
            loading_animation.running = False
            animation_thread.join()
            
            return json.loads(response)
        except json.JSONDecodeError:
            # Make sure to stop animation even if there's an error
            loading_animation.running = False
            animation_thread.join()
            return {
                "component_found": False,
                "direct_usage": False,
                "usage_details": "Failed to analyze code"
            }
        except Exception as e:
            # Make sure to stop animation even if there's an error
            loading_animation.running = False
            animation_thread.join()
            raise e

# Example usage (only runs if script is executed directly)
if __name__ == "__main__":
    # Test data
    file_info = {
        'file': '/home/mrbacardi/Machine_Learning_CTF_Challenges/Dolos_ML_CTF_Challenge/aiexecuter.py',
        'count': 2
    }
    
    component = "PALChain"
    confidence = "HIGH"

    # Create analyzer instance
    analyzer = CodeReviewer()
    
    # Analyze vulnerability
    result = analyzer.analyze_vulnerability(file_info, component, confidence)
    
    # Print results
    print("\nVulnerability Analysis Results:")
    print("=" * 50)
    print(json.dumps(result, indent=2))
