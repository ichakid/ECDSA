/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ecdsa;

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

    public Point getG() {
        return G;
    }

    public void setG(Point G) {
        this.G = G;
    }

    public Point getQA() {
        return QA;
    }
    
    
    
    public Point signatureGeneration(String m){
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
    }
    
    public boolean signatureVerification(String m, Point signature){
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
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
    }
    
}
