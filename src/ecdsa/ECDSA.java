/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ecdsa;

import java.util.ArrayList;

/**
 *
 * @author User
 */
public class ECDSA {
    private long dA;    //private key of sender 'A', a randomly selected int less than n
    private long n;     //the order of the curve
    private Curve curve;    //the elliptic curve
    private Point G;        //the generator point, an elliptic curve domain parameter
    private Point QA;    //public key of sender 'A'

    public ECDSA(long n) {
        this.n = n;
        curve.setP(n);
        G = new Point();
        QA = new Point();
    }

    public long getdA() {
        return dA;
    }

    public void setdA(long dA) {
        this.dA = dA;
        QA = G.multiplication(this.dA);
    }

    public void setG(Point G) {
        this.G = G;
    }

    public Point getQA() {
        return QA;
    }
    
    public ArrayList<Point> getEllipticGroup(){
        return curve.ellipticGroup;
    }
    
    //For signing a message m by sender A, using A’s private key dA
    //Returns signature in hex string representation
    public String signingMessage(String m) throws Exception{
        Point signPoint = signatureGeneration(m);
        String signPointString = signPoint.toString();
        return getHexString(signPointString.getBytes());
    }
    
    //For checking A's signature in message m. Signature is in hex string representation
    //Returns true if the signature is valid, returns false if it is invalid
    public boolean checkSignature(String m, String signature){
        String signPointString = new String(hexStringToByteArray(signature));
        String[] splitted = signPointString.split("\\s+");
        Point signPoint = new Point(Long.parseLong(splitted[0]), Long.parseLong(splitted[1]));
        return signatureVerification(m, signPoint); 
    }
    
    //For generating a signature using private key dA on message m
    //Returns signature in point representation
    private Point signatureGeneration(String m){
        // e = HASH(m)
        long k, r, s;
        Point x1y1 = new Point();
        do{
            x1y1 = G.multiplication(k);
            r = x1y1.getX() % n;
            if (r != 0){
                //s = k^-1(e + dAr)(mod n)
            }
        } while ((r == 0) || (s == 0));
        Point signature = new Point(r, s);
        return signature;
    }
    
    //Authenticate A's point signature
    //Returns true if the signature is valid, returns false if it is invalid
    private boolean signatureVerification(String m, Point signature){
        long r = signature.getX();
        long s = signature.getY();
        if ((r >= 1) && (r <= n-1) && (s >= 1) && (s <= n-2)){
            // e = HASH(m)
            // w = s^-1 (mod n)
            // u1 = ew (mod n)
            // u2 = rw (mod n)
            Point x1y1 = new Point();
            // x1y1 = G.multiplication(u1);
            // x1y1.addition(QA.multiplication(u2));
            if (x1y1.getX() == (r % n)){
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }
    
    //Returns hex string representation of byte array
    private String getHexString(byte[] b) throws Exception {
        String result = "";
        for (int i=0; i < b.length; i++) {
          result +=
                Integer.toString( ( b[i] & 0xff ) + 0x100, 16).substring( 1 );
        }
        return result;
    }
    
    //Returns byte array of a string
    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception {
        // TODO code application logic here
        long n = 131;
        ECDSA app = new ECDSA(n);
        for (Point p : app.getEllipticGroup()){
            System.out.println("P(" + p.getX() + "," + p.getY() +")");
        }
        Point G = new Point();
        app.setG(G);
        long dA = 8;
        app.setdA(dA);
        Point QA = app.getQA();
        System.out.println("Order of curve: " + n);
        System.out.println("Private key of sender 'A': " + dA);
        System.out.println("Generating point: G(" + G.getX() + "," + G.getY() + ")");
        System.out.println("Public key of sender 'A': QA(" + QA.getX() + "," + QA.getY() + ")");
        String m = "";
        String signature = app.signingMessage(m);
        System.out.println("Message: " + m);
        System.out.println("Signature: " + signature);
        boolean check = app.checkSignature(m, signature);
        System.out.println("Signature verification: " + check);
    }
    
}
