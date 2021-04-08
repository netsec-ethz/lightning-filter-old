This subdirectory contains the metrics exporter.
It is the interface between the Lightning Filter application and the local 
Prometheus server.

The application listens on the UNIX socket: "/tmp/echo.sock" and exports 
Prometheus data on port 8080.

To run:
1. Make sure that your local Prometheus server is running and that Prometheus
   is configured to listen to port 8080.
2. Run metrics exporter by calling: go run metrics_exporter.go
3. Abort with Ctrl+C at any time.

In order to modify the export port or the UNIX socket to listen on the source file must be modified.

In oder to export new metrics:
1. Add the new variable (see Prometheus doc or copy & modify existing variable)
2. Add the variable to the initPrometheus function to register
3. Modify the echo server function and either add a new parse function or modify an existing one