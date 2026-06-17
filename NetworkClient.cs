using System;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace krbengine
{
    public class NetworkClient
    {
        // Отправка Kerberos-сообщения на KDC по TCP и получение ASN.1-ответа
        public static async Task<byte[]> SendKerberosPacketAsync(byte[] payload, string dcIp, int port = 88)
        {
            try
            {
                byte[] lengthBytes = BitConverter.GetBytes(payload.Length);
                if (BitConverter.IsLittleEndian) Array.Reverse(lengthBytes);

                byte[] packet = new byte[lengthBytes.Length + payload.Length];
                Buffer.BlockCopy(lengthBytes, 0, packet, 0, lengthBytes.Length);
                Buffer.BlockCopy(payload, 0, packet, lengthBytes.Length, payload.Length);

                using (var tcpClient = new TcpClient())
                {
                    var connectTask = tcpClient.ConnectAsync(dcIp, port);
                    if (await Task.WhenAny(connectTask, Task.Delay(5000)) != connectTask)
                    {
                        throw new TimeoutException("KDC не отвечает (Таймаут).");
                    }

                    using (var stream = tcpClient.GetStream())
                    {
                        await stream.WriteAsync(packet, 0, packet.Length);

                        // Чтение заголовка длины ответа
                        byte[] responseLengthBuf = new byte[4];
                        int headerRead = await stream.ReadAsync(responseLengthBuf, 0, 4);
                        if (headerRead < 4) return null;

                        if (BitConverter.IsLittleEndian) Array.Reverse(responseLengthBuf);
                        int responseLength = BitConverter.ToInt32(responseLengthBuf, 0);

                        // Чтение тела ответа ASN.1
                        byte[] responseData = new byte[responseLength];
                        int totalRead = 0;
                        while (totalRead < responseLength)
                        {
                            int read = await stream.ReadAsync(responseData, totalRead, responseLength - totalRead);
                            if (read == 0) break;
                            totalRead += read;
                        }

                        return responseData;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"    [-] Сетевая ошибка транспорта: {ex.Message}");
                Console.ResetColor();
                return null;
            }
        }
    }
}