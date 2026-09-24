import sys
import json
from src.analysis_service import AnalysisService

def main():
    """
    Main entry point for the PhishGuard CLI.
    """
    print("Welcome to PhishGuard Phase 5: Hybrid ML + Explainable Heuristic Analysis")
    print("Enter a URL to analyze, or type 'exit' to quit.")
    
    analysis_service = AnalysisService()
    
    while True:
        try:
            user_input = input("\nEnter URL: ").strip()
            
            if user_input.lower() in ('exit', 'quit'):
                break
                
            if not user_input:
                continue
                
            # Perform Analysis
            analysis = analysis_service.analyze(user_input)
            
            # Present the results
            print("\nPHISHGUARD ANALYSIS")
            print("-------------------")
            print(f"\nNormalized URL:\n{analysis['normalized_url']}")
            print(f"\nOVERALL ASSESSMENT: {analysis['overall_assessment']}")
            print(f"{analysis['agreement_status']}\n")
            
            print("--- HEURISTIC ANALYSIS ---")
            print(f"Risk Score: {analysis['heuristic']['risk_score']}/100")
            print(f"Risk Level: {analysis['heuristic']['risk_level']}\n")
            
            if analysis['heuristic']['indicators']:
                for ind in analysis['heuristic']['indicators']:
                    print(f"[+{ind['points']}] {ind['indicator']}")
                    print(f"{ind['explanation']}\n")
            else:
                print("No significant heuristic risk indicators detected.\n")
                
            print("--- ML ANALYSIS ---")
            if analysis['ml'].get('available'):
                print(f"Model: {analysis['ml']['model']}")
                print(f"Prediction: {analysis['ml']['prediction_label']}")
                print(f"Phishing Probability: {analysis['ml']['phishing_probability']*100:.1f}%")
                print(f"Benign Probability: {analysis['ml']['benign_probability']*100:.1f}%\n")
            else:
                print("ML analysis unavailable.\n")
            
        except EOFError:
            break
        except ValueError as e:
            print(f"[-] Validation Error: {e}")
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"[-] An unexpected error occurred: {e}")
            break

if __name__ == "__main__":
    main()
