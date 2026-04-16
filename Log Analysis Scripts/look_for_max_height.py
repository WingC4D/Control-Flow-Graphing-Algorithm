from re import findall
from sys import argv
def main(argc:int , argv: list[str])->None:
    if (argc < 1):
        return print("[!] Please input a log's file name to analyse.\nThe log file must be placed under the \"Test Logs\" directory.")
    
    
    with open(argv[1], 'r') as file:
        contents      : str       = file.read()
        matches       : list[str] = findall(r"\[i\] Analyzing Block Of Linear Index [0-9 a-fx]{6} & Of Height: ([0-9 a-fx]{4})", contents)
        unique_matches: list[int] = [int(match, 0) for match in set(matches)]
        print(len(unique_matches))
        
        
if __name__ == "__main__":
    main(len(argv), argv)