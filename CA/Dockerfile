# Start from a base image containing the Go runtime
FROM golang:latest

# Set the current working directory inside the container
WORKDIR /go/src/app

# Copy the local package files to the container's workspace
COPY . .

# Build the Go app
RUN go build -o main .

# Expose port 8080 to the outside world
EXPOSE 8080

# Command to run the executable
CMD ["./main"]
