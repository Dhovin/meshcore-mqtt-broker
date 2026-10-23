/**
 * MQTT Stream Packet Size Validator
 *
 * Inspects incoming byte chunks at the transport (WebSocket) layer before
 * Aedes buffers them in memory. In MQTT, the fixed header consists of:
 * - Byte 0: Control Packet Type & Flags
 * - Bytes 1-4: Remaining Length encoded as a Variable Byte Integer
 *
 * If any packet claims a Remaining Length exceeding `maxPacketBytes`,
 * or if the Remaining Length encoding is malformed (> 4 bytes),
 * this validator immediately flags it so the connection can be terminated.
 */
export class MqttStreamValidator {
  private state: 'HEADER' | 'LENGTH' | 'PAYLOAD' = 'HEADER';
  private remainingLength = 0;
  private lengthMultiplier = 1;
  private lengthBytesRead = 0;
  private payloadBytesRemaining = 0;

  constructor(private readonly maxPacketBytes: number) {}

  /**
   * Process a chunk of incoming data.
   * Returns null if valid, or an Error if packet length exceeds limit or is malformed.
   */
  processChunk(chunk: Buffer): Error | null {
    let offset = 0;

    while (offset < chunk.length) {
      if (this.state === 'HEADER') {
        // Read 1-byte MQTT fixed header
        offset++;
        this.state = 'LENGTH';
        this.remainingLength = 0;
        this.lengthMultiplier = 1;
        this.lengthBytesRead = 0;
      } else if (this.state === 'LENGTH') {
        const byte = chunk[offset++];
        this.lengthBytesRead++;
        this.remainingLength += (byte & 0x7f) * this.lengthMultiplier;
        this.lengthMultiplier *= 128;

        if (this.remainingLength > this.maxPacketBytes) {
          return new Error(
            `MQTT packet remaining length (${this.remainingLength}) exceeds maximum allowed size of ${this.maxPacketBytes} bytes`
          );
        }

        if ((byte & 0x80) === 0) {
          // Finished variable length integer
          if (this.remainingLength === 0) {
            this.state = 'HEADER';
          } else {
            this.state = 'PAYLOAD';
            this.payloadBytesRemaining = this.remainingLength;
          }
        } else if (this.lengthBytesRead >= 4) {
          return new Error('Malformed MQTT packet: remaining length exceeds 4 bytes');
        }
      } else if (this.state === 'PAYLOAD') {
        const available = chunk.length - offset;
        if (available < this.payloadBytesRemaining) {
          this.payloadBytesRemaining -= available;
          offset = chunk.length;
        } else {
          offset += this.payloadBytesRemaining;
          this.payloadBytesRemaining = 0;
          this.state = 'HEADER';
        }
      }
    }

    return null;
  }
}
