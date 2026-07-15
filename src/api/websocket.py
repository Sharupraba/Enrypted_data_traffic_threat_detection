from fastapi import WebSocket
from typing import List
import logging

logger = logging.getLogger("zenith.api.websocket")

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Active connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Active connections: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """
        Broadcast a dictionary message as JSON to all active WebSocket clients.
        """
        disconnected_clients = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.warning(f"Error sending message to WebSocket client: {e}. Marking for cleanup.")
                disconnected_clients.append(connection)
                
        for client in disconnected_clients:
            self.disconnect(client)

# Global connection manager instance
manager = ConnectionManager()
