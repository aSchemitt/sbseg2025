package com.sbseg2025;

import java.security.Provider;
import java.security.Security;
import java.util.Enumeration;

import org.bouncycastle.jce.ECNamedCurveTable;

public class BCUtils {
    
    public static void PrintProviders() {
        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            System.out.println("-----");
            System.out.println(provider.getName());
            System.out.println(provider.getInfo());
            System.out.println("-----");
        }
    }

    public static void ListServices() {
        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            if (provider.getName().equals("BCPQC")) {
                System.out.println("Provider: "+provider.getName());
                for (Provider.Service service : provider.getServices()) {
                    System.out.println("  Algorithm: " + service.getAlgorithm() + " - Type: " + service.getType());
                }
            }
        }
    }

    public static void getCurves() {
        Enumeration e = ECNamedCurveTable.getNames();
        
        while (e.hasMoreElements()) {
            System.out.println(e.nextElement());
        }
    }

    // public static void main(String[] args) {
        // System.out.println("PRE configuration");
        // PrintProviders();
        // Configurations.configure();
        // System.out.println("====================================================================");
        // System.out.println("POS configuration");
        // PrintProviders();
        
        // ListServices();
        // getCurves();
    // }
}
