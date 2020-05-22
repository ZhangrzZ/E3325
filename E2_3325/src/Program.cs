using System;
using System.IO.Ports;
using System.Threading;

public class PortChat
{
    static bool _continue;
    static SerialPort _serialPort;

    public static void Main()
    {
        _serialPort = new SerialPort();
        string name;
        string message;
        Thread readThread = new Thread(Read);
        StringComparer stringComparer = StringComparer.OrdinalIgnoreCase;
        
        
        string portName, defaultPortName = null;
        string baudRate, defaultPortBaudRate = null;
        string parity, defaultPortParity = null;
        string dataBits, defaultPortDataBits = null;
        string stopBits, defaultPortStopBits = null;
        string handshake, defaultPortHandshake = null;

        Console.WriteLine("Available Ports:");
        foreach (string s in SerialPort.GetPortNames()) Console.WriteLine("   {0}", s);

        Console.Write("Enter COM port value (Default: {0}): ", defaultPortName);
        portName = Console.ReadLine();
        Console.Write("Baud Rate(default:{0}): ", defaultPortBaudRate);
        baudRate = Console.ReadLine();


        //portname
        if (portName == "" || !(portName.ToLower()).StartsWith("com"))
            portName = defaultPortName;
        _serialPort.PortName = portName;
        //portbaudrate
        if (baudRate == "")
            baudRate = defaultPortBaudRate.ToString();
        _serialPort.BaudRate = int.Parse(baudRate);



        Console.WriteLine("Available Parity options:");
        foreach (string s in Enum.GetNames(typeof(Parity)))
            Console.WriteLine("   {0}", s);

        Console.Write("Enter Parity value (Default: {0}):", defaultPortParity.ToString(), true);
        parity = Console.ReadLine();
        Console.Write("Enter DataBits value (Default: {0}): ", defaultPortDataBits);
        dataBits = Console.ReadLine();

        //portparity
        if (parity == "")
            parity = defaultPortParity.ToString();
        _serialPort.Parity = (Parity)Enum.Parse(typeof(Parity), parity, true);
        //portdatabits
        if (dataBits == "")
            dataBits = defaultPortDataBits.ToString();
        _serialPort.DataBits = int.Parse(dataBits.ToUpperInvariant());


        Console.WriteLine("Available StopBits options:");
        foreach (string s in Enum.GetNames(typeof(StopBits)))
            Console.WriteLine("   {0}", s);

        Console.Write("Enter StopBits value (None is not supported and \n" +
         "raises an ArgumentOutOfRangeException. \n (Default: {0}):", defaultPortStopBits.ToString());
        stopBits = Console.ReadLine();

        Console.WriteLine("Available Handshake options:");
        foreach (string s in Enum.GetNames(typeof(Handshake)))
            Console.WriteLine("   {0}", s);

        Console.Write("Enter Handshake value (Default: {0}):", defaultPortHandshake.ToString());
        handshake = Console.ReadLine();

        //portstopbits
        if (stopBits == "")
            stopBits = defaultPortStopBits.ToString();
        _serialPort.StopBits = (StopBits)Enum.Parse(typeof(StopBits), stopBits, true);
        //porthandshake
        if (handshake == "")
            handshake = defaultPortHandshake.ToString();
        _serialPort.Handshake = (Handshake)Enum.Parse(typeof(Handshake), handshake, true);

        _serialPort.ReadTimeout = 500;
        _serialPort.WriteTimeout = 500;

        _serialPort.Open();
        _continue = true;
        readThread.Start();

        Console.Write("Name: ");
        name = Console.ReadLine();

        while (_continue)
        {
            message = Console.ReadLine();

            if (stringComparer.Equals("quit", message))
                _continue = false;
            else
                _serialPort.WriteLine(String.Format("<{0}>: {1}", name, message));
        }

        readThread.Join();
        _serialPort.Close();
    }

    public static void Read()
    {
        while (_continue)
        {
            try
            {
                string message = _serialPort.ReadLine();
                Console.WriteLine(message);
            }
            catch (TimeoutException) { }
        }
    }
}