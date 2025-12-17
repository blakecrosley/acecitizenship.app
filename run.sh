#!/bin/bash

# Ace Citizenship Marketing Site - Development Server
# Usage: ./run.sh [start|stop|restart|status]

PORT=8080
PID_FILE=".server.pid"
LOG_FILE=".server.log"
VENV_DIR=".venv"

cd "$(dirname "$0")"

# Activate virtual environment
if [ -d "$VENV_DIR" ]; then
    source "$VENV_DIR/bin/activate"
else
    echo "Virtual environment not found. Creating..."
    python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"
    pip install -r requirements.txt
fi

start() {
    if [ -f "$PID_FILE" ] && kill -0 $(cat "$PID_FILE") 2>/dev/null; then
        echo "Server is already running (PID: $(cat $PID_FILE))"
        return 1
    fi

    echo "Starting server on port $PORT..."
    nohup "$VENV_DIR/bin/uvicorn" app.main:app --host 0.0.0.0 --port $PORT --reload > "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"
    sleep 1

    if kill -0 $(cat "$PID_FILE") 2>/dev/null; then
        echo "Server started (PID: $(cat $PID_FILE))"
        echo "Open http://localhost:$PORT"
    else
        echo "Failed to start server. Check $LOG_FILE for details."
        rm -f "$PID_FILE"
        return 1
    fi
}

stop() {
    if [ ! -f "$PID_FILE" ]; then
        echo "Server is not running (no PID file)"
        return 1
    fi

    PID=$(cat "$PID_FILE")
    if kill -0 $PID 2>/dev/null; then
        echo "Stopping server (PID: $PID)..."
        kill $PID
        sleep 1
        if kill -0 $PID 2>/dev/null; then
            kill -9 $PID
        fi
        echo "Server stopped"
    else
        echo "Server process not found"
    fi
    rm -f "$PID_FILE"
}

status() {
    if [ -f "$PID_FILE" ] && kill -0 $(cat "$PID_FILE") 2>/dev/null; then
        echo "Server is running (PID: $(cat $PID_FILE)) on port $PORT"
        echo "URL: http://localhost:$PORT"
    else
        echo "Server is not running"
        rm -f "$PID_FILE" 2>/dev/null
    fi
}

logs() {
    if [ -f "$LOG_FILE" ]; then
        tail -f "$LOG_FILE"
    else
        echo "No log file found"
    fi
}

case "${1:-start}" in
    start)   start ;;
    stop)    stop ;;
    restart) stop; sleep 1; start ;;
    status)  status ;;
    logs)    logs ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        exit 1
        ;;
esac
