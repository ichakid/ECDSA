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
public class Point {
    private long x;
    private long y;
    private long a;
    public static Point O = new Point(Long.MAX_VALUE, Long.MAX_VALUE);

    public Point() {
        this.x = 0;
        this.y = 1; 
        this.a = 6;
    }
    
    public Point(long x, long y) {
        this.x = x;
        this.y = y;
        this.a = 6;
    }

    public void setA(long a) {
        this.a = a;
    }
    
    public long getX() {
        return x;
    }

    public void setX(long x) {
        this.x = x;
    }

    public long getY() {
        return y;
    }

    public void setY(long y) {
        this.y = y;
    }
    
    public Point copy(){
        Point r = new Point(this.x, this.y);
        r.setA(this.a);
        return r;
    }
    
    //Returns the inverse of point
    public Point inverse(){
        Point r = new Point(this.x, -this.y);
        r.setA(this.a);
        return r;
    }
    
    //Returns point result of addition between the point and another point
    public Point addition(Point q){
        Point r = new Point();
        if (q == O){
            return this.copy();
        } else if (this == O){
            return q;
        } else if (this.inverse() == q){
            return O;
        } else if (this.x == q.getX()){
            return O;
        } else {
            long lambda = ((this.y - q.getY())/(this.x - q.getX()));  //Calculate the gradient of line
            long _x = (lambda * lambda - this.x - q.getX());
            long _y = (lambda * (this.x - _x) - this.y) ;
            r.setX(_x);
            r.setY(_y);
            return r;
        }
    }
    
    //Returns point result of subtraction between the point and aother point. P +(-Q)
    public Point subtraction(Point q){
        Point r = new Point();
        r = this.addition(q.inverse());
        return r;
    }
    
    //Returns point result of addition between the point and itself
    public Point doubling(){
        if (this.y == 0){
            return O;
        } else {
            Point r = new Point();
            long lambda = (3 * this.x * this.x + this.a)/(2 * y);  //Menghitung gradien garis
            lambda = lambda ;
            long _x = (lambda * lambda - 2 * this.x) ;
            long _y = ((lambda * (this.x - _x) - this.y)) ;
            r.setX(_x);
            r.setY(_y);            
            return r;
        }
    }
    
    //Returns point result of addition between the point and itself for k-1 times
    public Point iteration(long k){
        Point r = this.copy();
        for (long i=1; i<k-1; i++){
            r.addition(this);
        }
        return r;
    }
    
    //Returns point result of multiplication between the point and scalar k
    //The point multiplication is obtained by rounding two basic elliptic kurve:
    //1. Point Addition (P + Q = R)
    //2. Point Doubling (2P = R)
    public Point multiplication(long k){
        Point r = new Point();
        if (k == 0){
            return O;
        }
        if (k == 1){
            return this.copy();
        } else if (k % 2 == 1) {
            r = this.addition(this.multiplication(k-1));
            return r;
        } else {
            Point temp = this.doubling();
            r = temp.multiplication(k/2);
            return r;
        }
    }
    
    //Returns a string representation of point
    public String toString(){
        String r = "" + x + " " + y;
        return r;
    }
}
