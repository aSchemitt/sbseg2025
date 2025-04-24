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
        String ecdsa256 = "SHA256withECDSA";
        String ecdsa384 = "SHA384withECDSA";
        String currentAlgorithm = ecdsa256;
        String currentProvider = "BC";
        // String currentProvider = "BCPQC";
        
        // run with ECDSA 256
        runTests(currentAlgorithm, currentProvider);
        currentAlgorithm = ecdsa384;
        // run with ECDSA 384
        runTests(currentAlgorithm, currentProvider);
        currentAlgorithm = fips204;
        // run with ML-DSA
        runTests(currentAlgorithm, currentProvider);
        currentAlgorithm = fips205;
        // run with SLH-DSA
        runTests(currentAlgorithm, currentProvider);
        
    }

    public static void runTests(String currentAlgorithm, String currentProvider) {
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
            long sigStartTime, sigElapsedTime, verifyStartTime, verifyElapsedTime;
            double sumSign = 0.0, sumVerify = 0.0;
            ArrayList<String> signMeasures = new ArrayList<>();
            ArrayList<String> verifyMeasures = new ArrayList<>();
            ArrayList<String> sizeMeasures = new ArrayList<>();
            long startTime, elapsedTime;

            startTime = System.nanoTime();
            for (int i = 0; i < numbOfIterations; i++) {
                sigStartTime = System.nanoTime();
                signature = SignData(priv, data, currentAlgorithm, currentProvider);
                sigElapsedTime = System.nanoTime() - sigStartTime;
                
                verifyStartTime = System.nanoTime();
                VerifyData(pub, data, signature, currentAlgorithm, currentProvider);
                verifyElapsedTime = System.nanoTime() - verifyStartTime;

                sizeMeasures.add(String.valueOf(signature.length));

                sumSign += sigElapsedTime;
                signMeasures.add(String.valueOf(sigElapsedTime));
                sumVerify += verifyElapsedTime;
                verifyMeasures.add(String.valueOf(verifyElapsedTime));
                data = updateData(data);
            }
            elapsedTime = System.nanoTime() - startTime;
            
            // Step 7 & 8
            // Calculate mean and standard deviation &
            // Save measured times to a file
            saveCalculateMeasures(signMeasures, verifyMeasures, sumSign, sumVerify, elapsedTime, currentAlgorithm);
            // Save measured sizes to a file
            saveSizes(sizeMeasures, currentAlgorithm);

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
    public static void saveCalculateMeasures(List<String> signMeasures, List<String> verifyMeasures, double sumSign, double sumVerify, long totalTime, String algorithm) {
        // sign
        double signMean, signStandardDeviationBase = 0.0, signStandardDeviationSamples = 0.0, signStandardDeviationPopulation = 0.0;
        signMean = sumSign / signMeasures.size();

        String fileDir = "results/sign/";
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
            for (String string : signMeasures) {
                writer.write(string + "\n");
                // double aux = Double.parseDouble(string.split(";")[0]) - mean;
                double aux = Double.parseDouble(string) - signMean;
                signStandardDeviationBase += Math.pow(aux, 2.0);
            }
            signStandardDeviationSamples = (Math.sqrt(signStandardDeviationBase / (signMeasures.size() - 1))) ;
            signStandardDeviationPopulation = (Math.sqrt(signStandardDeviationBase / (signMeasures.size()))) ;
            System.out.println("mean: " + (signMean) + " ns");
            System.out.println("standard deviation samples: " + signStandardDeviationSamples + " ns");
            System.out.println("standard deviation population: " + signStandardDeviationPopulation + " ns");

            writer.write("\nmean: " + (signMean) + " ns");
            writer.write("\nstandard deviation samples: " + signStandardDeviationSamples + " ns");
            writer.write("\nstandard deviation population: " + signStandardDeviationPopulation + " ns");
            writer.write("\ntotal time of signatures: "+ (totalTime) + " ns");
        } catch (Exception e) {
            System.out.println(e);
        }

        // verify
        double verifyMean, verifyStandardDeviationBase = 0.0, verifyStandardDeviationSamples = 0.0, verifyStandardDeviationPopulation = 0.0;
        verifyMean = sumVerify / verifyMeasures.size();

        fileDir = "results/verify/";
        fileName = algorithm+".txt";
        filePath = fileDir + fileName;

        // Create the directory, if not exists
        dir = new File(fileDir);
        if (!dir.exists()) {
            boolean created = dir.mkdirs();
            if (!created) {
                System.err.println("Unable to create directory: " + dir.getPath());
            }
        }

        try (FileWriter writer = new FileWriter(filePath)) {
            for (String string : signMeasures) {
                writer.write(string + "\n");
                // double aux = Double.parseDouble(string.split(";")[0]) - mean;
                double aux = Double.parseDouble(string) - verifyMean;
                verifyStandardDeviationBase += Math.pow(aux, 2.0);
            }
            verifyStandardDeviationSamples = (Math.sqrt(verifyStandardDeviationBase / (verifyMeasures.size() - 1))) ;
            verifyStandardDeviationPopulation = (Math.sqrt(verifyStandardDeviationBase / (verifyMeasures.size()))) ;
            System.out.println("mean: " + (verifyMean) + " ns");
            System.out.println("standard deviation samples: " + verifyStandardDeviationSamples + " ns");
            System.out.println("standard deviation population: " + verifyStandardDeviationPopulation + " ns");

            writer.write("\nmean: " + (verifyMean) + " ns");
            writer.write("\nstandard deviation samples: " + verifyStandardDeviationSamples + " ns");
            writer.write("\nstandard deviation population: " + verifyStandardDeviationPopulation + " ns");
            writer.write("\ntotal time of verifies: "+ (totalTime) + " ns");
        } catch (Exception e) {
            System.out.println(e);
        }
    }


    public static void saveSizes(List<String> sizes, String algorithm) {
        String fileDir = "results/sizes/";
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
            long sum = 0L;
            for (String s : sizes) {
                writer.write(s+"\n");
                sum += Long.parseLong(s);
            }
            writer.write("\nmean: "+(sum/sizes.size())+" B");
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    // Generic
    // TODO verificar inicialização dos algoritmos PQC
    public static KeyPair GenerateKeyPair(String algorithm, String provider) throws Exception {
        KeyPairGenerator keyPairGenerator;
        // ECDSA
        if (algorithm.equals("SHA256withECDSA") || algorithm.equals("SHA384withECDSA")) {
            ECGenParameterSpec Spec = null;
            if (algorithm.startsWith("SHA256")) {
                Spec = new ECGenParameterSpec("secp256k1");
            }
            if (algorithm.startsWith("SHA384")) {
                Spec = new ECGenParameterSpec("secp384r1");
            }

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
