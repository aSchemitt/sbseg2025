package com.sbseg2025;

import java.io.File;
import java.io.FileWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;

public class Calculations {
    /*
     * Steps
     * 1 - Configure bouncy castle as provider
     * 2 - Select algorithm
     * 3 - Generate or load keys
     * 4 - Creates the initial data
     * 5 - Perform the warm-up (1000 signatures)
     * 6 - Performs the signatures
     * I - Defines the number of iterations (10000)
     * II - Sign
     * III - Measures and saves time
     * IV - Update the data
     * 7 - Calculates mean and standard deviation
     * 8 - Save measurements to a file
     */

    private static SecureRandom rng;

    public static void main(String[] args) {
        // Step 1
        // Configure the Bouncy Castle as a security provider
        Configurations.configure();

        // Step 2
        // Algorithms options
        String fips204 = "ML-DSA";
        String fips205 = "SLH-DSA";
        String ecdsa = "SHA256withECDSA";
        String currentAlgorithm = ecdsa;
        String currentProvider = "BC";
        // String currentProvider = "BCPQC";

        try {
            // Step 3
            // Generate the keys
            KeyPair keys = GenerateKeyPair(currentAlgorithm, currentProvider);
            PrivateKey priv = keys.getPrivate();
            PublicKey pub = keys.getPublic();

            // Step 4
            // Generate random data
            byte[] data = generateData(1024);

            // Step 5
            // Warmup
            int WarmupIterations = 1_000;
            for (int i = 0; i < WarmupIterations; i++) {
                SignData(priv, data, currentAlgorithm, currentProvider);
            }
            
            // Step 6
            // Sign the transactions
            int numbOfIterations = 10_000;
            byte[] signature = null;
            long sigStartTime, sigElapsedTime;
            double sum = 0.0;
            ArrayList<String> measures = new ArrayList<>();
            long startTime, elapsedTime;

            startTime = System.nanoTime();
            for (int i = 0; i < numbOfIterations; i++) {
                sigStartTime = System.nanoTime();
                signature = SignData(priv, data, currentAlgorithm, currentProvider);
                sigElapsedTime = System.nanoTime() - sigStartTime;
                
                sum += sigElapsedTime;
                measures.add(String.valueOf(sigElapsedTime));
                data = updateData(data);
            }
            elapsedTime = System.nanoTime() - startTime;
            
            // Step 7 & 8
            // Calculate mean and standard deviation &
            // Save measured times to a file
            saveCalculateMeasures(measures, sum, elapsedTime, currentAlgorithm);

        } catch (Exception e) {
            System.out.println(e);
        }
    }

    // Generate random data
    public static byte[] generateData(int byteLenght) {
        rng = new SecureRandom();
        byte[] temp = new byte[byteLenght];
        System.out.println("RNG: " + rng.getAlgorithm());
        rng.nextBytes(temp);

        return temp;
    }

    // Update a random Byte
    public static byte[] updateData(byte[] data) {
        data[rng.nextInt(data.length)] = (byte) rng.nextInt(256);
        return data;
    }

    // Saves measured data and calculates mean and standard deviation
    public static void saveCalculateMeasures(List<String> measures, double sum, long totalTime, String algorithm) {
        double mean, standardDeviationBase = 0.0, standardDeviationSamples = 0.0, standardDeviationPopulation = 0.0;
        mean = sum / measures.size();

        String fileDir = "results/";
        String fileName = algorithm+".txt";
        String filePath = fileDir + fileName;

        // Create the directory, if not exists
        File dir = new File(fileDir);
        if (!dir.exists()) {
            boolean created = dir.mkdirs();
            if (!created) {
                System.err.println("Unable to create directory: " + dir.getPath());
            }
        }

        try (FileWriter writer = new FileWriter(filePath)) {
            for (String string : measures) {
                writer.write(string + "\n");
                // double aux = Double.parseDouble(string.split(";")[0]) - mean;
                double aux = Double.parseDouble(string) - mean;
                standardDeviationBase += Math.pow(aux, 2.0);
            }
            standardDeviationSamples = (Math.sqrt(standardDeviationBase / (measures.size() - 1))) ;
            standardDeviationPopulation = (Math.sqrt(standardDeviationBase / (measures.size()))) ;
            System.out.println("mean: " + (mean) + " ns");
            System.out.println("standard deviation samples: " + standardDeviationSamples + " ns");
            System.out.println("standard deviation population: " + standardDeviationPopulation + " ns");

            writer.write("\nmean: " + (mean) + " ns");
            writer.write("\nstandard deviation samples: " + standardDeviationSamples + " ns");
            writer.write("\nstandard deviation population: " + standardDeviationPopulation + " ns");
            writer.write("\ntotal time of signatures: "+ (totalTime) + " ns");
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    // Generic
    // TODO verificar inicialização dos algoritmos PQC
    public static KeyPair GenerateKeyPair(String algorithm, String provider) throws Exception {
        KeyPairGenerator keyPairGenerator;
        // ECDSA
        if (algorithm.equals("SHA256withECDSA")) {
            ECGenParameterSpec Spec = new ECGenParameterSpec("secp256k1");

            keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", provider);
            keyPairGenerator.initialize(Spec, new SecureRandom());
        } else { // ML-DSA or SLH-DSA
            keyPairGenerator = KeyPairGenerator.getInstance(algorithm, provider);

        }

        System.out.println("Keys generated by " + keyPairGenerator.getAlgorithm());
        return keyPairGenerator.generateKeyPair();
    }

    // Generic
    public static byte[] SignData(PrivateKey key, byte[] data, String algorithm, String provider) throws Exception {
        Signature signer = Signature.getInstance(algorithm, provider);
        signer.initSign(key);
        signer.update(data);
        // System.out.println("signature algorithm: "+signer.getAlgorithm());//+";
        // parameters: "+signer.getParameters().toString());
        return signer.sign();
    }

    // Generic
    public static boolean VerifyData(PublicKey key, byte[] data, byte[] signature, String algorithm, String provider)
            throws Exception {
        Signature verifier = Signature.getInstance(algorithm, provider);
        verifier.initVerify(key);
        verifier.update(data);
        // System.out.println("Verify algorithm: "+verifier.getAlgorithm());//+";
        // parameters: "+signer.getParameters().toString());
        return verifier.verify(signature);
    }

}
