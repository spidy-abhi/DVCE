from colorama import Fore, Style
import re
from pathlib import Path
import os

class ComponentSearcher:
    def extract_context(self, content: str, pattern: str, context_chars: int) -> list:
        """
        Extract surrounding context for matched patterns.
        """
        contexts = []
        matches = re.finditer(pattern, content, re.IGNORECASE)
        
        for match in matches:
            start = max(0, match.start() - context_chars)
            end = min(len(content), match.end() + context_chars)
            context = content[start:end].strip()
            contexts.append(context)
        
        return contexts

    def search_component_in_code(self, root_dir: str, component_name: str) -> dict:
        """
        Search for a specific component in Python code files.
        """
        results = {
            'direct_imports': [],
            'usage_in_code': [],
            'string_references': [],
            'related_components': []
        }
        
        # Compile regex patterns
        import_pattern = re.compile(rf'(?:from|import).*{component_name}')
        usage_pattern = re.compile(rf'\b{component_name}\b')
        
        # Split component name to identify key terms for related component search
        component_terms = set(re.findall('[A-Z][a-z]{1,}', component_name))
        #print(f"Looking for related components with terms: {component_terms}")
        
        # Walk through all Python files in the directory
        for root, _, files in os.walk(root_dir):
            for file in files:
                if file.endswith('.py'):
                    file_path = Path(root) / file
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                            # Check for imports
                            imports = import_pattern.findall(content)
                            if imports:
                                results['direct_imports'].append({
                                    'file': str(file_path),
                                    'imports': imports
                                })
                            
                            # Check for direct usage in code
                            usages = usage_pattern.findall(content)
                            if usages:
                                results['usage_in_code'].append({
                                    'file': str(file_path),
                                    'count': len(usages)
                                })
                            
                            # Look for related components using component terms
                            found_terms = []
                            for term in component_terms:
                                if term.lower() in content.lower():
                                    found_terms.append(term)
                            
                            if len(found_terms) >= 2:  # At least 2 terms match
                                print(f"\nFound related component in {file_path}")
                                print(f"Matching terms: {found_terms}")
                                context = self.extract_context(content, '|'.join(found_terms), 100)
                                
                                results['related_components'].append({
                                    'file': str(file_path),
                                    'matching_terms': found_terms,
                                    'context': context
                                })
                                
                    except Exception as e:
                        print(f"Error processing {file_path}: {str(e)}")
        
        return results

    def __call__(self, vulnerable_component: str, folder_path: str) -> dict:
        """
        Check if vulnerable component exists in codebase.
        """
        try:
            #print(f"\n{Fore.GREEN}Searching for: {vulnerable_component}{Style.RESET_ALL}")
            results = self.search_component_in_code(folder_path, vulnerable_component)
            print(f"\n{Fore.YELLOW}Static (Non-AI) Code Analysis {Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Files with component: {Style.RESET_ALL}{vulnerable_component}")
            for result in results['usage_in_code']:
                print(f"{Fore.YELLOW}Usage in code: {Style.RESET_ALL}{result['file']}")
            for result in results['direct_imports']:
                print(f"{Fore.YELLOW}Direct imports: {Style.RESET_ALL}{result['file']}")
            for result in results['related_components']:
                print(f"{Fore.YELLOW}Related components: {Style.RESET_ALL}{result['file']}")    

            # Determine confidence level
            has_direct_imports = len(results.get('direct_imports', [])) > 0
            has_usage = len(results.get('usage_in_code', [])) > 0
            has_related = len(results.get('related_components', [])) > 0
            
            if has_direct_imports or has_usage:
                confidence = "HIGH"
            elif has_related:
                confidence = "LOW"
            else:
                confidence = "NONE"
            
            # Print confidence
            confidence_color = Fore.RED if confidence == "HIGH" else Fore.CYAN if confidence == "LOW" else Fore.GREEN
            print(f"Potential to be vulnerable: {confidence_color}{confidence}{Style.RESET_ALL}")
            # Format results for compatibility with existing code
            return {
                "component_present": len(results['usage_in_code']) > 0 or len(results['direct_imports']) > 0,
                "confidence": "HIGH" if len(results['usage_in_code']) > 0 else "MEDIUM" if len(results['related_components']) > 0 else "LOW",
                "matches": results
            }
            
        except Exception as e:
            print(f"\nError details: {str(e)}")
            return {
                "error": f"Error during vulnerability check: {str(e)}",
                "component_present": False,
                "confidence": "LOW",
                "matches": []
            }
