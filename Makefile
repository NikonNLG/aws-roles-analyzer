mac:
	GOOS=darwin go build -o aws-roles-analyzer-mac .

linux:
	GOOS=linux go build -o aws-roles-analyzer-linux .

windows:
	GOOS=windows go build -o aws-roles-analyzer-windows.exe .
