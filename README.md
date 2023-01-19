# Prisma Cloud Compliance Export Helper
This tool creates a custom CSV based on compliance related findings in Prisma Cloud.

## Usage
### Installation
A few python packages are required to execute this script
```bash
pip3 install -r requirements.txt
```

### Credential setup
To access the data in the tenant the Username/Passwords/Tokens need to be provided as environemnt variables.
An example is given in the `.env.template`.

### Execution
Calling the help function
```bash
python3 main.py --help
```
To create a `out.csv` file use the following command:
```bash
python3 main.py --standard-name "ISO 27001:2013" --account-group "MyAccountGroup" --output-file "out.csv" --stack-name "api2.eu"
```

#### Example output
```
standard,requirement_name,requirement_id,section_id,account_name,account_id,provider,rrn
....
```
