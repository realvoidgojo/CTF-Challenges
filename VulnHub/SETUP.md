# How to Set Up Vulnhub Machines

## Prerequisites

Before starting, ensure you have the following installed:

- [VirtualBox](https://www.virtualbox.org/)
- [VMware](https://www.vmware.com/) (optional, some machines are VMware-compatible)
- A virtualization-capable computer

## Steps to Set Up Vulnhub Machines

### 1. Download the Virtual Machine

1. Visit the [Vulnhub website](https://www.vulnhub.com/).
2. Browse the list of available machines and select the one you want to download.
3. Click on the machine’s page and download the OVA file or the ZIP file containing the virtual machine files.

### 2. Import the Virtual Machine into VirtualBox

1. Open VirtualBox.
2. Click on `File` > `Import Appliance`.
3. Browse to the location of the downloaded OVA file or extracted VM files and select it.
4. Click `Next`, review the settings, and then click `Import`.

### 3. Configure Network Settings

1. Select the imported VM in VirtualBox.
2. Click on `Settings`.
3. Go to the `Network` section.
4. Ensure that `Adapter 1` is attached to `NAT` or `Bridged Adapter` depending on your network setup.
   - **NAT:** Allows the VM to access the internet through the host machine’s network.
   - **Bridged Adapter:** Connects the VM directly to your network, getting its own IP address.

### 4. Start the Virtual Machine

1. Select the VM in VirtualBox.
2. Click `Start`.
3. Wait for the VM to boot up. This might take a few moments.

### 5. Obtain the IP Address of the VM

1. Once the VM is booted, log in using the provided credentials (usually found on the Vulnhub machine’s download page).
2. Use the command `ifconfig` (Linux) or `ip a` to find the VM's IP address.
3. Note down the IP address for use in your penetration testing activities.

### 6. Access the VM

1. Use tools like `nmap` to scan the VM’s IP address to discover open ports and services.
2. Start your penetration testing activities using tools like `Metasploit`, `Burp Suite`, or other security testing tools.

## Additional Tips

- **Snapshots:** Before starting your testing, take a snapshot of the VM. This allows you to revert to a clean state if necessary.
- **Documentation:** Keep notes of your findings and steps taken during the exploitation process. This will help you track your progress and replicate successful exploits.
- **Practice:** Take your time to understand each step. Practice different attack vectors and techniques to enhance your skills.

## Common Commands

- **ifconfig/ip a:** Find the IP address of the VM.
- **nmap:** Scan the VM for open ports and services.
  ```bash
  nmap -sV [IP_ADDRESS]
  ```

## Additional Setup Resources

For detailed instructions on setting up Vulnhub machines, you can:

- Read my blog post on [How to Setup VulnHub Machine (vmdk) in Oracle VirtualBox](https://medium.com/@realvoidgojo/how-to-setup-vulnhub-machine-vmdk-in-oracle-virtualbox-0a602ec550e4) on Medium.
- Watch setup tutorials for each machine on YouTube.
