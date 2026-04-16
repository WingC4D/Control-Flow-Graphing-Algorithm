from re import findall
from sys import argv
def main(argc: int , argv: list[str])->None:
    if argc < 2:
        return print("[!] Please input a log's file name to analyse.\nThe log file must be placed under the \"Test Logs\" directory.")

    with open(argv[1], "r") as file:
        contents : str        = file.read()
        addresses:list[str]   = findall(r"@([0-9a-fx]{14})", contents)
        unique_addresses: set = set(addresses)
        num_of_addresses      = len(addresses)
        num_of_unique_address = len(unique_addresses)
        print(f"Total Instructions Traced:  {num_of_addresses}")
        print(f"Unique Instructions Mapped: {num_of_unique_address}")

        if num_of_addresses == num_of_unique_address:
            print("\n[+] SUCCESS: Zero duplicates.")
        else:
           print(f"\n[-] FAIL: Found {num_of_addresses - num_of_unique_address} duplicates.")

        seen = set()
        for addr in addresses:
            if addr in seen:
                print(f"Duplicate found at: {addr}")
            seen.add(addr)
    return

if __name__ == "__main__":
    main(len(argv), argv)