import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class Server {

    private JLabel TopLabel;
    private JLabel WriteLabel;
    private JTextField InputField;
    private JButton SendButton;
    private JPanel MainPanel;
    private JTextArea ShowMsg;
    static ObjectInputStream ois;
    static  ObjectOutputStream oos;



    static String secKey;
    private static ServerSocket server;
    private static int port = 9876;
    private static SecretKeySpec secretKey;
    private static byte[] key;

    public static String getHash(String input)
    {
        try {
            // getInstance() method is called with algorithm SHA-512
            MessageDigest md = MessageDigest.getInstance("SHA-512");

            // digest() method is called
            // to calculate message digest of the input string
            // returned as array of byte
            byte[] messageDigest = md.digest(input.getBytes());

            // Convert byte array into signum representation
            BigInteger no = new BigInteger(1, messageDigest);

            // Convert message digest into hex value
            String hashtext = no.toString(16);

            // Add preceding 0s to make it 32 bit
            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }

            // return the HashText
            return hashtext;
        }

        // For specifying wrong message digest algorithms
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }



    public static void setKey(String myKey) {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes(StandardCharsets.UTF_8);
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static String encrypt(String strToEncrypt, String secret) {
        try {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static String decrypt(String strToDecrypt, String secret) {
        try {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    public void SetValue(String msg){
        this.ShowMsg.append(msg);
    }

    public Server() {
        SendButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String outmsg="";
                outmsg = InputField.getText();
                System.out.println(outmsg);
                ShowMsg.append("\nYou: " + outmsg);
                outmsg = outmsg + "&&" + getHash(outmsg);
                try {
                    oos.writeObject(encrypt(outmsg, secKey));
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            }

        });
    }

    public static void main(String[] args) throws IOException, ClassNotFoundException {

        Server obj =  new Server();
        JFrame frame = new JFrame("Server");
        frame.setContentPane(obj.MainPanel);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(500, 400);
        //frame.pack();
        frame.setVisible(true);

        SecureRandom secRan = new SecureRandom();
        double Bdash = 0;
        Scanner sc = new Scanner(System.in);
        server = new ServerSocket(port);
        System.out.println("Waiting for client");
        Socket socket = server.accept();
        System.out.println("Just connected to " + socket.getRemoteSocketAddress());
        ois = new ObjectInputStream(socket.getInputStream());
        oos = new ObjectOutputStream(socket.getOutputStream());
        try {
            int port = 8088;
            int b = secRan.nextInt(10) + 1;
            double clientP, clientG, clientA, B;
            String Bstr;

            // Server's Private Key
            System.out.println("\nFrom Server : Private Key = " + b);
            // Accepts the data from client
            clientP = Integer.parseInt((String) ois.readObject()); // to accept p
            System.out.println("From Client : P = " + clientP);

            clientG = Integer.parseInt((String) ois.readObject()); // to accept g
            System.out.println("From Client : G = " + clientG);

            clientA = Double.parseDouble((String) ois.readObject()); // to accept A
            System.out.println("From Client : Public Key = " + clientA);

            B = ((Math.pow(clientG, b)) % clientP); // calculation of B
            Bstr = Double.toString(B);

            oos.writeObject(Bstr); // Sending B

            Bdash = ((Math.pow(clientA, b)) % clientP); // calculation of Bdash

            System.out.println("Secret Key to perform Symmetric Encryption = " + Bdash);
        } catch (SocketTimeoutException s) {
            System.out.println("Socket timed out!");
        } catch (IOException e) {
        }

        secKey = Double.toString(Bdash);

        String recvd = "";
        while (!recvd.equals("Exit")) {

            String asdf = (String) ois.readObject();
            recvd = decrypt(asdf, secKey);
            String[] message = recvd.split("&&");
            if (!getHash(message[0]).equals(message[1])) System.out.println("Authentication failed!!!");
            obj.SetValue("\nClient: " + message[0]);
            System.out.println("\nClient: " + message[0]);
            System.out.println(asdf);
        }
        ois.close();
        oos.close();
        socket.close();
        System.out.println("Server closed");
        server.close();
    }

}
