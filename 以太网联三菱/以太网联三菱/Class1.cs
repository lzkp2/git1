using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Text;
using System.Net;

namespace 以太网联三菱
{
    /// <summary>
    /// 三菱5U PLC以太网通信类
    /// 使用MC协议实现与三菱5U系列PLC的以太网通信
    /// </summary>
    public class MitsubishiPLC : IDisposable
    {
        #region 属性
        
        /// <summary>
        /// PLC的IP地址
        /// </summary>
        public string IpAddress { get; private set; }
        
        /// <summary>
        /// PLC的端口号，默认为502
        /// </summary>
        public int Port { get; private set; }
        
        /// <summary>
        /// 通信超时时间（毫秒）
        /// </summary>
        public int Timeout { get; set; }
        
        /// <summary>
        /// 当前连接状态
        /// </summary>
        public bool IsConnected { get; private set; }
        
        /// <summary>
        /// 用于通信的Socket对象
        /// </summary>
        private Socket _socket;
        
        #endregion
        
        #region 构造函数
        
        /// <summary>
        /// 初始化PLC通信类
        /// </summary>
        /// <param name="ipAddress">PLC的IP地址</param>
        /// <param name="port">PLC的端口号，默认为502</param>
        public MitsubishiPLC(string ipAddress, int port = 502)
        {
            IpAddress = ipAddress;
            Port = port;
            Timeout = 5000; // 默认超时时间为5秒
            IsConnected = false;
        }
        
        #endregion
        
        #region 连接管理方法
        
        /// <summary>
        /// 连接到PLC
        /// </summary>
        public void Connect()
        {
            try
            {
                // 创建TCP Socket
                _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                
                // 设置超时
                _socket.ReceiveTimeout = Timeout;
                _socket.SendTimeout = Timeout;
                
                // 连接到PLC
                _socket.Connect(IpAddress, Port);
                
                IsConnected = true;
            }
            catch (Exception ex)
            {
                IsConnected = false;
                throw new Exception($"连接PLC失败: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// 异步连接到PLC
        /// </summary>
        public async Task ConnectAsync()
        {
            try
            {
                // 创建TCP Socket
                _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                
                // 设置超时
                _socket.ReceiveTimeout = Timeout;
                _socket.SendTimeout = Timeout;
                
                // 异步连接到PLC
                await _socket.ConnectAsync(IpAddress, Port);
                
                IsConnected = true;
            }
            catch (Exception ex)
            {
                IsConnected = false;
                throw new Exception($"异步连接PLC失败: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// 断开与PLC的连接
        /// </summary>
        public void Disconnect()
        {
            try
            {
                if (_socket != null && IsConnected)
                {
                    _socket.Shutdown(SocketShutdown.Both);
                    _socket.Close();
                }
            }
            finally
            {
                _socket = null;
                IsConnected = false;
            }
        }
        
        #endregion
        
        #region 数据读写方法
        
        /// <summary>
        /// 读取PLC的位元件（如X,Y,M,Q等）
        /// </summary>
        /// <param name="device">设备名称，如"M100"</param>
        /// <returns>位元件的值</returns>
        public bool ReadBit(string device)
        {
            var (code, address) = ParseDevice(device);
            
            // 构建读取位命令
            byte[] command = BuildCommand(0x01, code, address, 1);
            
            // 发送命令并接收响应
            byte[] response = SendCommand(command);
            
            // 解析响应 - 位数据在响应的第12个字节开始
            if (response.Length >= 13)
            {
                return response[12] > 0;
            }
            
            throw new Exception("无效的响应数据长度");
        }
        
        /// <summary>
        /// 异步读取PLC的位元件
        /// </summary>
        /// <param name="device">设备名称</param>
        /// <returns>位元件的值</returns>
        public async Task<bool> ReadBitAsync(string device)
        {
            return await Task.Run(() => ReadBit(device));
        }
        
        /// <summary>
        /// 写入PLC的位元件（如X,Y,M,Q等）
        /// </summary>
        /// <param name="device">设备名称，如"M100"</param>
        /// <param name="value">要写入的值</param>
        public void WriteBit(string device, bool value)
        {
            var (code, address) = ParseDevice(device);
            
            // 构建写入位命令 - 写入命令需要额外的数据部分
            byte[] command = new byte[22]; // 基础命令长度+数据长度
            byte[] baseCommand = BuildCommand(0x02, code, address, 1);
            
            // 复制基础命令
            Array.Copy(baseCommand, command, baseCommand.Length);
            
            // 设置写入数据
            command[20] = 0x00; // 子命令
            command[21] = (byte)(value ? 1 : 0); // 写入值
            
            // 发送命令并接收响应
            SendCommand(command);
        }
        
        /// <summary>
        /// 异步写入PLC的位元件
        /// </summary>
        /// <param name="device">设备名称</param>
        /// <param name="value">要写入的值</param>
        public async Task WriteBitAsync(string device, bool value)
        {
            await Task.Run(() => WriteBit(device, value));
        }
        
        /// <summary>
        /// 读取PLC的字元件（如D,W等）
        /// </summary>
        /// <param name="device">设备名称，如"D100"</param>
        /// <returns>字元件的值</returns>
        public short ReadWord(string device)
        {
            short[] values = ReadWords(device, 1);
            return values.Length > 0 ? values[0] : (short)0;
        }
        
        /// <summary>
        /// 异步读取PLC的字元件
        /// </summary>
        /// <param name="device">设备名称</param>
        /// <returns>字元件的值</returns>
        public async Task<short> ReadWordAsync(string device)
        {
            return await Task.Run(() => ReadWord(device));
        }
        
        /// <summary>
        /// 写入PLC的字元件（如D,W等）
        /// </summary>
        /// <param name="device">设备名称，如"D100"</param>
        /// <param name="value">要写入的值</param>
        public void WriteWord(string device, short value)
        {
            WriteWords(device, new short[] { value });
        }
        
        /// <summary>
        /// 异步写入PLC的字元件
        /// </summary>
        /// <param name="device">设备名称</param>
        /// <param name="value">要写入的值</param>
        public async Task WriteWordAsync(string device, short value)
        {
            await Task.Run(() => WriteWord(device, value));
        }
        
        /// <summary>
        /// 读取多个PLC的字元件（如D,W等）
        /// </summary>
        /// <param name="device">起始设备名称，如"D100"</param>
        /// <param name="count">读取的数量</param>
        /// <returns>字元件的值数组</returns>
        public short[] ReadWords(string device, int count)
        {
            if (count <= 0)
                throw new ArgumentOutOfRangeException(nameof(count), "读取数量必须大于0");
            
            var (code, address) = ParseDevice(device);
            
            // 构建读取字命令
            byte[] command = BuildCommand(0x01, code, address, count);
            
            // 发送命令并接收响应
            byte[] response = SendCommand(command);
            
            // 解析响应 - 字数据在响应的第12个字节开始，每个字占2个字节
            if (response.Length >= 12 + count * 2)
            {
                short[] values = new short[count];
                for (int i = 0; i < count; i++)
                {
                    // MC协议使用大端序
                    values[i] = (short)((response[12 + i * 2] << 8) | response[13 + i * 2]);
                }
                return values;
            }
            
            throw new Exception("无效的响应数据长度");
        }
        
        /// <summary>
        /// 异步读取多个PLC的字元件
        /// </summary>
        /// <param name="device">起始设备名称</param>
        /// <param name="count">读取的数量</param>
        /// <returns>字元件的值数组</returns>
        public async Task<short[]> ReadWordsAsync(string device, int count)
        {
            return await Task.Run(() => ReadWords(device, count));
        }
        
        /// <summary>
        /// 写入多个PLC的字元件（如D,W等）
        /// </summary>
        /// <param name="device">起始设备名称，如"D100"</param>
        /// <param name="values">要写入的值数组</param>
        public void WriteWords(string device, short[] values)
        {
            if (values == null || values.Length == 0)
                throw new ArgumentException("写入值数组不能为空", nameof(values));
            
            var (code, address) = ParseDevice(device);
            
            // 构建写入字命令 - 写入命令需要额外的数据部分
            int dataLength = values.Length * 2; // 每个字2个字节
            byte[] command = new byte[20 + 2 + dataLength]; // 基础命令长度+子命令长度+数据长度
            
            // 设置基础命令部分
            command[0] = 0x50; // 子头部固定值
            command[1] = 0x00;
            command[2] = 0x00; // 网络编号
            command[3] = 0xFF; // PC编号
            command[4] = 0x03; // 请求目标模块IO编号
            command[5] = 0x00; // 请求目标模块站号
            command[6] = 0x00; // 预留
            command[7] = 0x00; // 预留
            
            // 请求数据长度 = 子命令(2) + 数据长度
            int requestLength = 2 + dataLength;
            command[8] = (byte)((requestLength >> 8) & 0xFF);
            command[9] = (byte)(requestLength & 0xFF);
            
            command[10] = 0x00; // CPU监控定时器
            command[11] = 0x0A; // 100ms
            command[12] = 0x02; // 命令类型：写入
            command[13] = 0x00; // 子命令
            
            // 设备代码映射
            Dictionary<string, byte[]> deviceCodeMap = new Dictionary<string, byte[]>()
            {
                { "X", new byte[] { 0x9C } },  // 输入继电器
                { "Y", new byte[] { 0x9D } },  // 输出继电器
                { "M", new byte[] { 0x90 } },  // 内部继电器
                { "D", new byte[] { 0xA8 } },  // 数据寄存器
                { "W", new byte[] { 0xB4 } },  // 链接寄存器
                { "L", new byte[] { 0x92 } },  // 锁存继电器
                { "F", new byte[] { 0x93 } },  // 报警器
                { "S", new byte[] { 0x94 } },  // 状态继电器
                { "T", new byte[] { 0x95 } },  // 定时器
                { "C", new byte[] { 0x96 } },  // 计数器
                { "DT", new byte[] { 0xA9 } }  // 数据寄存器(扩展)
            };
            
            // 设置设备代码
            if (deviceCodeMap.TryGetValue(code, out byte[] codeBytes))
            {
                if (codeBytes.Length > 0)
                    command[14] = codeBytes[0];
                if (codeBytes.Length > 1)
                    command[15] = codeBytes[1];
            }
            else
            {
                throw new NotSupportedException($"不支持的设备类型: {code}");
            }
            
            // 设置地址
            command[16] = (byte)((address >> 8) & 0xFF);
            command[17] = (byte)(address & 0xFF);
            
            // 设置数量
            command[18] = (byte)((values.Length >> 8) & 0xFF);
            command[19] = (byte)(values.Length & 0xFF);
            
            // 子命令
            command[20] = 0x00;
            command[21] = 0x00;
            
            // 设置写入数据（大端序）
            for (int i = 0; i < values.Length; i++)
            {
                command[22 + i * 2] = (byte)((values[i] >> 8) & 0xFF);
                command[23 + i * 2] = (byte)(values[i] & 0xFF);
            }
            
            // 发送命令并接收响应
            SendCommand(command);
        }
        
        /// <summary>
        /// 异步写入多个PLC的字元件
        /// </summary>
        /// <param name="device">起始设备名称</param>
        /// <param name="values">要写入的值数组</param>
        public async Task WriteWordsAsync(string device, short[] values)
        {
            await Task.Run(() => WriteWords(device, values));
        }
        
        #endregion
        
        #region 资源管理
        
        /// <summary>
        /// 释放资源
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        
        /// <summary>
        /// 释放资源
        /// </summary>
        /// <param name="disposing">是否手动释放</param>
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                // 释放托管资源
                Disconnect();
            }
            // 释放非托管资源（如果有）
        }
        
        /// <summary>
        /// 析构函数
        /// </summary>
        ~MitsubishiPLC()
        {
            Dispose(false);
        }
        
        #endregion
        
        #region 私有辅助方法
        
        /// <summary>
        /// 根据设备名称解析出设备代码和地址
        /// </summary>
        /// <param name="device">设备名称，如"D100"</param>
        /// <returns>包含设备代码和地址的元组</returns>
        private (string code, int address) ParseDevice(string device)
        {
            if (string.IsNullOrEmpty(device))
                throw new ArgumentNullException(nameof(device), "设备名称不能为空");
            
            // 提取设备代码（前1-2个字符）
            string code = string.Empty;
            int address = 0;
            int codeLength = 1;
            
            // 对于双字符设备代码（如"DT"）
            if (device.Length > 2 && char.IsLetter(device[0]) && char.IsLetter(device[1]))
            {
                code = device.Substring(0, 2);
                codeLength = 2;
            }
            else if (char.IsLetter(device[0]))
            {
                // 单字符设备代码（如"D"）
                code = device.Substring(0, 1);
            }
            else
            {
                throw new ArgumentException($"无效的设备名称格式: {device}", nameof(device));
            }
            
            // 提取地址部分
            if (int.TryParse(device.Substring(codeLength), out address))
            {
                return (code, address);
            }
            else
            {
                throw new ArgumentException($"无法从设备名称中解析地址: {device}", nameof(device));
            }
        }
        
        /// <summary>
        /// 构建MC协议的命令报文
        /// </summary>
        /// <param name="commandType">命令类型</param>
        /// <param name="deviceCode">设备代码</param>
        /// <param name="address">设备地址</param>
        /// <param name="count">数量</param>
        /// <returns>命令报文的字节数组</returns>
        private byte[] BuildCommand(byte commandType, string deviceCode, int address, int count)
        {
            // 验证参数
            if (address < 0)
                throw new ArgumentOutOfRangeException(nameof(address), "地址不能为负数");
            
            if (count <= 0)
                throw new ArgumentOutOfRangeException(nameof(count), "数量必须大于0");
            
            // 三菱MC协议帧格式（二进制格式）
            // 这里实现基本的读取/写入命令构建
            byte[] command = new byte[20]; // 标准帧长度
            
            // 子头部
            command[0] = 0x50; // 子头部固定值
            command[1] = 0x00;
            
            // 网络编号
            command[2] = 0x00;
            
            // PC编号
            command[3] = 0xFF;
            
            // 请求目标模块IO编号
            command[4] = 0x03;
            
            // 请求目标模块站号
            command[5] = 0x00;
            
            // 预留
            command[6] = 0x00;
            command[7] = 0x00;
            
            // 请求数据长度 (2 bytes)
            command[8] = 0x00;
            command[9] = 0x0C;
            
            // CPU监控定时器 - 使用可配置的值
            command[10] = 0x00;
            command[11] = (byte)((Timeout / 10) & 0xFF); // 转换为10ms为单位
            
            // 命令类型
            command[12] = commandType; // 0x01: 读取，0x02: 写入
            
            // 子命令
            command[13] = 0x00;
            
            // 获取设备代码映射 - 提取为单独的方法以提高可维护性
            byte[] codeBytes = GetDeviceCodeBytes(deviceCode);
            
            // 设置设备代码
            if (codeBytes.Length > 0)
                command[14] = codeBytes[0];
            if (codeBytes.Length > 1)
                command[15] = codeBytes[1];
            
            // 设置地址 (2 bytes)
            command[16] = (byte)((address >> 8) & 0xFF);
            command[17] = (byte)(address & 0xFF);
            
            // 设置数量 (2 bytes)
            command[18] = (byte)((count >> 8) & 0xFF);
            command[19] = (byte)(count & 0xFF);
            
            return command;
        }
        
        /// <summary>
        /// 获取设备代码对应的字节数组
        /// </summary>
        /// <param name="deviceCode">设备代码</param>
        /// <returns>设备代码字节数组</returns>
        private byte[] GetDeviceCodeBytes(string deviceCode)
        {
            Dictionary<string, byte[]> deviceCodeMap = new Dictionary<string, byte[]>()
            {
                { "X", new byte[] { 0x9C } },  // 输入继电器
                { "Y", new byte[] { 0x9D } },  // 输出继电器
                { "M", new byte[] { 0x90 } },  // 内部继电器
                { "D", new byte[] { 0xA8 } },  // 数据寄存器
                { "W", new byte[] { 0xB4 } },  // 链接寄存器
                { "L", new byte[] { 0x92 } },  // 锁存继电器
                { "F", new byte[] { 0x93 } },  // 报警器
                { "S", new byte[] { 0x94 } },  // 状态继电器
                { "T", new byte[] { 0x95 } },  // 定时器
                { "C", new byte[] { 0x96 } },  // 计数器
                { "DT", new byte[] { 0xA9 } }  // 数据寄存器(扩展)
            };
            
            if (deviceCodeMap.TryGetValue(deviceCode, out byte[] codeBytes))
            {
                return codeBytes;
            }
            else
            {
                throw new NotSupportedException($"不支持的设备类型: {deviceCode}");
            }
        }
        
        /// <summary>
        /// 发送命令并接收响应
        /// </summary>
        /// <param name="command">命令字节数组</param>
        /// <returns>响应字节数组</returns>
        private byte[] SendCommand(byte[] command)
        {
            if (!IsConnected || _socket == null)
                throw new InvalidOperationException("未连接到PLC");
            
            try
            {
                // 发送命令
                _socket.Send(command);
                
                // 接收响应 - 使用更可靠的接收方式
                byte[] buffer = new byte[4096]; // 增大缓冲区
                int totalBytesRead = 0;
                int bytesRead;
                
                // 设置单次读取超时
                _socket.ReceiveTimeout = Timeout;
                
                // 循环接收，直到收到完整响应或超时
                while (totalBytesRead < buffer.Length)
                {
                    try
                    {
                        bytesRead = _socket.Receive(buffer, totalBytesRead, buffer.Length - totalBytesRead, SocketFlags.None);
                        if (bytesRead == 0) break; // 连接关闭
                        totalBytesRead += bytesRead;
                        
                        // 检查是否已收到完整响应（至少包含基本响应头）
                        if (totalBytesRead >= 12)
                        {
                            // 对于MC协议，可以根据实际需求添加更精确的响应完整性检查
                            break;
                        }
                    }
                    catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
                    {
                        throw new TimeoutException("接收PLC响应超时", ex);
                    }
                }
                
                // 复制有效数据
                byte[] response = new byte[totalBytesRead];
                Array.Copy(buffer, response, totalBytesRead);
                
                // 检查响应是否有错误
                if (response.Length >= 12 && response[11] != 0)
                {
                    string errorMessage = GetErrorMessage(response[11]);
                    throw new Exception($"PLC响应错误: 错误代码 {response[11]} - {errorMessage}");
                }
                
                return response;
            }
            catch (Exception ex)
            {
                IsConnected = false;
                Disconnect();
                throw new Exception($"通信失败: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// 根据错误代码获取错误描述
        /// </summary>
        /// <param name="errorCode">错误代码</param>
        /// <returns>错误描述</returns>
        private string GetErrorMessage(byte errorCode)
        {
            Dictionary<byte, string> errorMap = new Dictionary<byte, string>()
            {
                { 0x01, "命令格式错误" },
                { 0x02, "命令未定义" },
                { 0x03, "参数错误" },
                { 0x04, "处理数据范围错误" },
                { 0x05, "处理数据长度错误" },
                { 0x06, "数据类型错误" },
                { 0x07, "访问路径错误" },
                { 0x08, "数据不足错误" },
                { 0x09, "设备忙" },
                { 0x0A, "操作被拒绝" },
                { 0x0B, "内存不足" },
                { 0x0C, "其他错误" }
            };
            
            if (errorMap.TryGetValue(errorCode, out string message))
                return message;
            return "未知错误";
        }
        
        #endregion
    }
}
