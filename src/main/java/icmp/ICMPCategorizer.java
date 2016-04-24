package icmp;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;

/**
 * <h1>ICMP Categorizer</h1>
 * ICMPCategorizer utilises the tcpdump commandline tool to categorise packet data into the respective ICMP categories
 * @author Michael Kyeyune
 * @since 2016-04-21
 */
public class ICMPCategorizer
{
    // the instruction messages to be printed out in case of an error
    private static final String FILE_ARGUMENT_INSTRUCTION = "- Provide a file to read with the -f flag e.g java ICMPCategorizer -f sample_file";
    private static final String FOLDER_ARGUMENT_INSTRUCTION = "- Provide a folder to read files from with the -d flag e.g java ICMPCategorizer -d sample_folder";

    private static DateFormat DATE_FORMAT = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");

    public static void main(String[] args)
    {
        if(args.length == 0)
        {
            System.out.println("No arguments provided. Please do one of the following:");
            System.out.println(FILE_ARGUMENT_INSTRUCTION);
            System.out.println(FOLDER_ARGUMENT_INSTRUCTION);
        }
        else if(args.length == 2)
        {
            DATE_FORMAT = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");

            if(args[0].equals("-f"))
            {
                System.out.println("======================================================================");
                printCurrentTime();
                String fileName = args[1];
                System.out.println("Preparing to process file: " + fileName);
                HashMap<String, Integer> ICMPCategoryMap = new HashMap<String, Integer>();
                updateICMPCategoryTallyWithFile(ICMPCategoryMap, fileName);
                printOutTally(ICMPCategoryMap);
            }
            else if(args[0].equals("-d"))
            {
                String folderName = args[1];

                File folder = new File(folderName);
                HashMap<String, Integer> ICMPCategoryMap = new HashMap<String, Integer>();

                System.out.println("======================================================================");
                System.out.println("Preparing to process files in folder: " + folderName);

                for(String fileName: folder.list())
                {
                    fileName = folderName + "/" + fileName;
                    System.out.println("======================================================================");
                    printCurrentTime();
                    System.out.println("Preparing to process file: " + fileName);
                    updateICMPCategoryTallyWithFile(ICMPCategoryMap, fileName);
                    printOutTally(ICMPCategoryMap);
                }
            }
            else
            {
                System.out.println("Wrong arguments provided. Please do one of the following:");
                System.out.println(FILE_ARGUMENT_INSTRUCTION);
                System.out.println(FOLDER_ARGUMENT_INSTRUCTION);
            }
        }
        else
        {
            System.out.println("More arguments than expected provided. Please do one of the following:");
            System.out.println(FILE_ARGUMENT_INSTRUCTION);
            System.out.println(FOLDER_ARGUMENT_INSTRUCTION);
        }
    }

    /*
     * Updates the tally of the provided ICMP Category Map
     * @param ICMPCategoryMap The hashmap containing the ICMP message categories and their current counts
     * @param fileName The name of the file to read from and update the category counts
     */
    private static void updateICMPCategoryTallyWithFile(HashMap<String, Integer> ICMPCategoryMap, String fileName)
    {
        ProcessBuilder processBuilder = new ProcessBuilder("tcpdump" ,"-t", "icmp", "and not src net 192.168.0.0/16", "and not src net 10.0.0.0/8" ,"-r", fileName);
        try
        {
            printCurrentTime();
            System.out.println("Running tcpdump on file: " + fileName);
            Process process = processBuilder.start();
            int errorCode = process.waitFor();

            BufferedReader bufferedReader = null;
            String line = null;

            if(errorCode == 0)
            {
                printCurrentTime();
                System.out.println("No error occurred on running tcpdump command for file: " + fileName);


                bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));

                while((line = bufferedReader.readLine()) != null)
                {

                    //remove message length
                    String tempString = (line.split(","))[0];
                    tempString = tempString.trim();
                    //System.out.println(tempString);

                    //get the icmp message
                    String icmpMessage = (tempString.split(":"))[1];
                    icmpMessage = icmpMessage.trim();
                    //System.out.println(icmpMessage);

                    String icmpCategory = null;

                    if(icmpMessage.contains("unreachable"))
                        icmpCategory = "ICMP Destination unreachable";
                    else
                        icmpCategory = icmpMessage;

                    Integer currentCount = 1;

                    if(ICMPCategoryMap.containsKey(icmpCategory))
                    {
                        //increase the count for this icmp category
                        currentCount = ICMPCategoryMap.get(icmpCategory);
                        currentCount++;
                    }

                    ICMPCategoryMap.put(icmpCategory, currentCount);
                }
            }
            else
            {
                printCurrentTime();
                System.out.println("An error occurred while running tcpdump command for file: " + fileName);
                bufferedReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));

                while((line = bufferedReader.readLine()) != null)
                {
                    System.out.println(line);
                }

            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    private static void printCurrentTime()
    {
        System.out.print(DATE_FORMAT.format(new Date()) + " ");
    }

    private static void printOutTally(HashMap<String, Integer> ICMPCategoryMap)
    {
        if(ICMPCategoryMap.isEmpty())
        {
            printCurrentTime();
            System.out.println("No ICMP data found.");
        }
        else
        {
            printCurrentTime();
            System.out.println("The current tally is as follows:");

            for(String key: ICMPCategoryMap.keySet())
            {
                System.out.println(key + " : " + ICMPCategoryMap.get(key));
            }
        }
    }
}
