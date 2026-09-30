from typing import TypedDict, Annotated, Sequence
from langgraph.graph import Graph, StateGraph, START, END
import requests
import sys
import json
import os
import chromadb
from chromadb.utils import embedding_functions
from datetime import datetime
from colorama import init, Fore, Style
import re
from pathlib import Path
from check_components import ComponentSearcher
from review_code import CodeReviewer
import time
import threading
from dotenv import load_dotenv
from athena_client import prompt_athena

init()  # Initialize colorama

# Load environment variables
load_dotenv()

def loading_animation():
    """Show loading animation like a terminal loading bar"""
    #shapes = ["◴", "◷", "◶", "◵"]
    #shapes = ["⏳", "⌛"]
    shapes = ["🕐", "🕑", "🕒", "🕓", "🕔", "🕕", "🕖", "🕗", "🕘", "🕙", "🕚", "🕛"]

    colors = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.BLUE, Fore.MAGENTA, Fore.CYAN]
    i = 0
    while loading_animation.running:
        color = colors[i % len(colors)]
        shape = shapes[i % len(shapes)]
        sys.stdout.write('\r' + f">> analyzing cve {color}{shape} {Style.RESET_ALL}")
        sys.stdout.flush()
        i += 1
        time.sleep(0.3)
    sys.stdout.write('\r' + ' ' * 50 + '\r')
    sys.stdout.flush()

# Define our state
class State(TypedDict):
    github_token: str
    advisory_id: str
    folder_path: str
    cve_description: str
    analysis_result: dict
    vuln_components: dict
    selected_keywords: list
    check_results: list
    vector_collection: any
    code_analysis_results: list
    error: str | None

# Tool for GitHub Advisory
class GithubAdvisoryTool:
    def __init__(self, github_token):
        self.github_token = github_token
        # Validate token on initialization
        self.validate_token()

    def validate_token(self):
        """Validate GitHub token by making a test API call"""
        headers = {
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
            'Authorization': f'Bearer {self.github_token}'
        }
        try:
            response = requests.get(
                'https://api.github.com/user',
                headers=headers
            )
            if response.status_code == 401:
                print(f"{Fore.RED}Error: Invalid GitHub token in .env file{Style.RESET_ALL}")
                print("Please check your token and make sure it has the necessary permissions")
                sys.exit(1)
        except requests.RequestException as e:
            print(f"{Fore.RED}Error validating GitHub token: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)

    def advisory_search(self, advisory_id):
        """Fetch CVE description from GitHub API."""
        headers = {
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
            'Authorization': f'Bearer {self.github_token}'
        }
        try:
            response = requests.get(
                f'https://api.github.com/advisories/{advisory_id}',
                headers=headers
            )
            response.raise_for_status()
            advisory_data = response.json()
            description = advisory_data.get('description', 'Description not available.')
            vulnerabilities = advisory_data.get('vulnerabilities', [])
            
            custom_string = ""
            if vulnerabilities:
                vuln = vulnerabilities[0]
                package = vuln.get('package', {}).get('name')
                version_range = vuln.get('vulnerable_version_range')
                first_patched_version = vuln.get('first_patched_version')
                custom_string = f"The vulnerable package is {package} and vulnerable versions of this package are {version_range}. The fixed version is {first_patched_version}. "
            print("\n")
            print(f"{Fore.YELLOW}Vulnerability Detail: {Style.RESET_ALL}{custom_string}.{description}")
            return custom_string, description
        except requests.RequestException as e:
            print(f"Error fetching advisory data: {e}")
            sys.exit(1)

# Agent for Vulnerable Component Identification
class SecurityAnalyst:
    def identify_vuln_component(self, discription):
        
        """Agent Task 2: Identify specific vulnerable components."""
        system_prompt = """
You are a precision-focused cybersecurity vulnerability extractor. Your primary task is to identify and isolate the exact vulnerable technical component from a given vulnerability description.

Input Analysis Objectives:
1. Identify the Specific Vulnerable Component
   - Extract the exact technical component, library, class, or method name
   - Prioritize named technologies or specific implementation details
   - Ignore generic descriptions and focus on precise identifiers

2. Extraction Criteria:
   - Look for:
     * Specific library names
     * Class names
     * Method names
     * Plugin or module identifiers
     * Precise technical components

3. Vulnerability Component Isolation Process:
   - Isolate the most specific technical term that represents the vulnerability
   - Provide context about why this component is considered vulnerable
   - Prepare a concise, actionable output for further investigation

Expected Output Format:
{
    "vulnerable_component": "EXACT_COMPONENT_NAME",
    "confidence": "HIGH/MEDIUM/LOW",
    "search_keywords": ["list", "of", "search", "terms"],
    "additional_context": "Brief explanation of vulnerability mechanism"
}
"""
        try:
            # Start animation
            loading_animation.running = True
            animation_thread = threading.Thread(target=loading_animation)
            animation_thread.start()

            # Model call
            response = prompt_athena(
                system_prompt + f"\n\nAnalyze this codebase behavior:\n{discription}\n"
            )

            # Stop animation after model response
            loading_animation.running = False
            animation_thread.join()
            
            try:
                result = json.loads(response)
            except json.JSONDecodeError:
                result = {
                    "vulnerable_component": "UNKNOWN",
                    "confidence": "LOW",
                    "search_keywords": [],
                    "additional_context": "Failed to parse LLM response",
                    "raw_response": response
                }
            
            return result
        
        except Exception as e:
            # Make sure to stop animation even if there's an error
            loading_animation.running = False
            animation_thread.join()
            return {
                "vulnerable_component": "ERROR",
                "confidence": "LOW",
                "search_keywords": [],
                "additional_context": f"Error during analysis: {str(e)}"
            }

# Define node functions
def fetch_cve_info(state: State) -> State:
    """Node 1: Fetch CVE information"""
    try:
        tool = GithubAdvisoryTool(state['github_token'])
        short_desc, cve_desc = tool.advisory_search(state['advisory_id'])
        return {**state, "cve_description": cve_desc}
    except Exception as e:
        return {**state, "error": f"Error fetching CVE info: {str(e)}"}
    
def identify_components(state: State) -> State:
    """Node 3: Identify vulnerable components"""
    try:
        agent = SecurityAnalyst()
        components = agent.identify_vuln_component(state['cve_description'])
        #print(components)
        return {**state, "vuln_components": components}
    except Exception as e:
        return {**state, "error": f"Error identifying components: {str(e)}"}

def get_user_selection(state: State) -> State:
    """Node 4: Get user input for keyword selection"""
    try:
        keywords = state['vuln_components'].get('search_keywords', [])
        if not keywords:
            return {**state, "selected_keywords": []}

        print(f"\n{Fore.YELLOW}Please select components from the listed search keywords:{Style.RESET_ALL}")
        for idx, keyword in enumerate(keywords, 1):
            print(f"{idx}. {keyword}")
        
        while True:
            selection = input(f"{Fore.YELLOW}Enter numbers (comma-separated) or 'all': {Style.RESET_ALL}")
            if selection.lower() == 'all':
                return {**state, "selected_keywords": keywords}
            
            try:
                indices = [int(idx.strip()) for idx in selection.split(',')]
                if all(1 <= idx <= len(keywords) for idx in indices):
                    selected = [keywords[idx-1] for idx in indices]
                    return {**state, "selected_keywords": selected}
            except ValueError:
                print("Invalid input. Try again.")
    except Exception as e:
        return {**state, "error": f"Error in user selection: {str(e)}"}

def check_components(state: State) -> State:
    """Node 4: Check for vulnerable components in codebase"""
    try:
        agent = ComponentSearcher()
        results = []
        for keyword in state['selected_keywords']:
            result = agent(keyword, state['folder_path'])
            results.append({"keyword": keyword, "result": result})
            
        return {**state, "check_results": results}
    except Exception as e:

        return {**state, "error": f"Error checking components: {str(e)}"}

def code_checker(state: State) -> State:
    """Node 5: Check code for vulnerable patterns using LLM"""
    try:
        analyzer = CodeReviewer()
        code_analysis_results = []
        
        print(f"\n{Fore.YELLOW}AI Code Analysis {Style.RESET_ALL}")
        #print(f"Number of check results: {len(state['check_results'])}")
        
        for result in state["check_results"]:
            component = result["keyword"]
            matches = result["result"].get("matches", {})
            
            # Get file paths based on priority
            file_paths = []
            if matches.get("usage_in_code"):
                file_paths = matches["usage_in_code"]
                confidence = "HIGH"
            elif matches.get("related_components"):
                # Extract string file paths from related_components
                file_paths = [str(item.get("file")) for item in matches["related_components"] if item.get("file")]
                confidence = "LOW"
            
            if not file_paths:
                print(f"{Fore.GREEN}No files to analyze for component: {Style.RESET_ALL}{component}")
                continue
                
            print(f"{Fore.YELLOW}Analyzing component: {Style.RESET_ALL}{component}")
            
            # Analyze each file
            for file_path in file_paths:
                # Ensure file_path is a string
                if isinstance(file_path, dict):
                    file_path = str(file_path.get("file", ""))
                else:
                    file_path = str(file_path)
                
                if not file_path:
                    continue
                
                #print(f"Checking file: {file_path}")
                
                file_info = {
                    "file": file_path,  # Now guaranteed to be a string
                    "count": 1
                }
                
                # Analyze vulnerability
                analysis_result = analyzer.analyze_vulnerability(file_info, component, confidence)
                code_analysis_results.append({
                        "component": component,
                        "file_path": file_path,
                        "confidence": confidence,
                        "analysis": analysis_result
                })
                """
                if analysis_result["component_found"] or analysis_result["direct_usage"]:
                    print(f"{Fore.YELLOW}Found potential vulnerability!{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}No direct vulnerability found.{Style.RESET_ALL}")
                """       

        return {**state, "code_analysis_results": code_analysis_results}
    except Exception as e:

        return {**state, "error": f"Error in code checker: {str(e)}"}

# Define the workflow
def create_workflow(
    github_token: str,
    advisory_id: str,
    folder_path: str
) -> StateGraph:
    # Create the graph
    workflow = StateGraph(State)

    # Add nodes
    workflow.add_node("fetch_cve", fetch_cve_info)
    workflow.add_node("identify_components", identify_components)
    workflow.add_node("get_selection", get_user_selection)
    workflow.add_node("check_components", check_components)
    workflow.add_node("code_checker", code_checker)

    # Add the entry point
    workflow.add_edge(START, "fetch_cve")

    # Add other edges
    workflow.add_edge("fetch_cve", "identify_components")
    workflow.add_edge("identify_components", "get_selection")
    workflow.add_edge("get_selection", "check_components")
    workflow.add_edge("check_components", "code_checker")

    # Set the end point
    workflow.add_edge("code_checker", END)

    return workflow

# Main execution
if __name__ == "__main__":
    # Get GitHub token from .env
    github_token = os.getenv('GITHUB_TOKEN')
    
    # Validate GitHub token
    if not github_token:
        print(f"{Fore.RED}Error: GITHUB_TOKEN not found in .env file{Style.RESET_ALL}")
        print("Please add your GitHub token to .env file as:")
        print("GITHUB_TOKEN=your_token_here")
        sys.exit(1)

    if len(sys.argv) != 3:
        print(f"{Fore.YELLOW}Usage: python script.py <advisory_id> <folder_path>{Style.RESET_ALL}")
        sys.exit(1)

    # Create and run workflow
    workflow = create_workflow(
        github_token=github_token,
        advisory_id=sys.argv[1],
        folder_path=sys.argv[2]
    )

    # Initialize state
    initial_state = State(
        github_token=github_token,
        advisory_id=sys.argv[1],
        folder_path=sys.argv[2],
        cve_description="",
        analysis_result={},
        vuln_components={},
        selected_keywords=[],
        check_results=[],
        code_analysis_results=[],
        error=None
    )

    # Compile the graph
    app = workflow.compile()

    # Run the workflow using .invoke() instead of .run()
    final_state = app.invoke(initial_state)

    # Print results
    if final_state.get("error"):
        print(f"\nError: {final_state['error']}")
    else:
        # Print code analysis results
        if final_state.get("code_analysis_results"):
            print(f"\n{Fore.YELLOW}AI Impact analyses results:{Style.RESET_ALL}")
            for result in final_state["code_analysis_results"]:
                print(f"\nComponent: {result['component']}")
                print(f"File: {result['file_path']}")
                confidence_color = Fore.RED if result['confidence'] == "HIGH" else Fore.CYAN if result['confidence'] == "LOW" else Fore.GREEN
                print(f"Likelihood of finding this component in code: {confidence_color}{result['confidence']}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Analysis Details:{Style.RESET_ALL}")
                analysis = result['analysis']
                # Color the boolean values
                component_found_color = Fore.RED if analysis["component_found"] else Fore.GREEN
                direct_usage_color = Fore.RED if analysis["direct_usage"] else Fore.GREEN
                # Print formatted output without using json.dumps()
                print("{")
                print(f'  "component_found": {component_found_color}{analysis["component_found"]}{Style.RESET_ALL},')
                print(f'  "direct_usage": {direct_usage_color}{analysis["direct_usage"]}{Style.RESET_ALL},')
                print(f'  "usage_details": "{analysis["usage_details"]}"')
                print("}")
        else:
            print(f"\n{Fore.GREEN}No vulnerable code patterns were found.{Style.RESET_ALL}")