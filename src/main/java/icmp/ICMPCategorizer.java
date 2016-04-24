package icmp;

import java.io.*;
import java.util.HashMap;
import java.util.Scanner;

/**
 * <h1>ICMP Categorizer</h1>
 * ICMPCategorizer utilises the tcpdump commandline tool to categorise packet data into the respective ICMP categories
 * @author Michael Kyeyune
 * @since 2016-04-21
 */
public class ICMPCategorizer
{
    // the instruction messages to be printed out in case of an error
    private static final String FOLDER_ARGUMENT_INSTRUCTION = "- Provide a folder to read files from with the -d flag e.g java ICMPCategorizer -d sample_folder";

    private static String CATEGORY_FOLDER_NAME = "data";

    public static void main(String[] args)
    {
        if(args.length == 0)
        {
            System.out.println("No arguments provided. Please do one of the following:");
            System.out.println(FOLDER_ARGUMENT_INSTRUCTION);
        }
        else if(args.length == 2)
        {
            if(args[0].equals("-d"))
            {
                String folderName = args[1];

                System.out.println("======================================================================");
                //delete the data folder if already created
                File dataFolder = new File(folderName + "/" + CATEGORY_FOLDER_NAME);

                if(dataFolder.exists())
                {
                    printCurrentTime();
                    System.out.println("Deleting data category folder in : " + folderName);
                    ICMPFilter.deleteDirectory(dataFolder);
                }

                dataFolder = new File(folderName + "/" + CATEGORY_FOLDER_NAME);

                printCurrentTime();
                if(dataFolder.mkdir())
                {
                    System.out.println("Created data category folder in : " + folderName);
                }
                else
                {
                    System.out.println("Failed to make data category folder in : " + folderName);
                    System.exit(1);
                }

                HashMap<String, HashMap<String, Integer>> ICMPCategoryMap = new HashMap<String, HashMap<String, Integer>>();

                System.out.println("======================================================================");
                printCurrentTime();
                System.out.println("Preparing to process icmp dumps in folder : " + folderName);

                File folder = new File(folderName);

                for(File file : folder.listFiles())
                {

                    if(file.isFile() && !file.isHidden())
                    {
                        System.out.println("======================================================================");
                        printCurrentTime();
                        System.out.println("Preparing to process file : " + folderName + "/" + file.getName());
                        writeICMPCategoryToFile(folderName, file.getName());
                    }

                }

                System.out.println("======================================================================");
                printCurrentTime();
                System.out.println("Beginning processing of categories");

                dataFolder = new File(folderName + "/" + CATEGORY_FOLDER_NAME);

                for(File file : dataFolder.listFiles())
                {
                    if(file.isFile() && !file.isHidden())
                    {
                        System.out.println("======================================================================");
                        printCurrentTime();
                        System.out.println("Analysing file : " + file.getName());

                        try {
                            Scanner scanner = new Scanner(file);

                            while(scanner.hasNextLine())
                            {
                                String line = scanner.nextLine();

                                if(!line.contains("!")) {
                                    String[] strArr = line.split(" ");

                                    if (!ICMPCategoryMap.containsKey(strArr[0])) {
                                        ICMPCategoryMap.put(strArr[0], new HashMap<String, Integer>());
                                    }

                                    if (!ICMPCategoryMap.get(strArr[0]).containsKey(strArr[1])) {
                                        ICMPCategoryMap.get(strArr[0]).put(strArr[1], 0);
                                    }

                                    int currentCount = ICMPCategoryMap.get(strArr[0]).get(strArr[1]);
                                    ICMPCategoryMap.get(strArr[0]).put(strArr[1], currentCount + 1);
                                }

                            }

                            printOutTally(ICMPCategoryMap);

                        } catch (FileNotFoundException e) {
                            e.printStackTrace();
                        }
                    }
                }

            }
            else
            {
                System.out.println("Wrong arguments provided. Please do one of the following:");
                System.out.println(FOLDER_ARGUMENT_INSTRUCTION);
            }
        }
        else
        {
            System.out.println("More arguments than expected provided. Please do one of the following:");
            System.out.println(FOLDER_ARGUMENT_INSTRUCTION);
        }
    }

    /*
     * Updates the tally of the provided ICMP Category Map
     * @param ICMPCategoryMap The hashmap containing the ICMP message categories and their current counts
     * @param fileName The name of the file to read from and update the category counts
     */
    private static void writeICMPCategoryToFile(String folderName, String fileName)
    {
        ProcessBuilder processBuilder = new ProcessBuilder("ipsumdump", "--icmp-type-name", "--icmp-code-name", "-r",
                folderName + "/" + fileName, "-o", folderName + "/" + CATEGORY_FOLDER_NAME + "/cat_" + fileName);

        try
        {
            printCurrentTime();
            System.out.println("Processing file : " + fileName);
            Process process = processBuilder.start();

            BufferedReader bufferedReader = null;
            String line = null;

            int errorCode = process.waitFor();

            if(errorCode == 0)
            {
                printCurrentTime();
                System.out.println("No error occurred on running ipsumdump command for file: " + fileName);

            }
            else
            {
                printCurrentTime();
                System.out.println("An error occurred while running ipsumdump for file : " + fileName);
                bufferedReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));

                while((line = bufferedReader.readLine()) != null)
                {
                    System.out.println(line);
                }
            }

        } catch (IOException e)
        {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public static void printCurrentTime()
    {
        ICMPFilter.printCurrentTime();
    }

    private static void printOutTally(HashMap<String, HashMap<String, Integer>> ICMPCategoryMap)
    {
        if(ICMPCategoryMap.isEmpty())
        {
            printCurrentTime();
            System.out.println("No ICMP data present as yet");
        }
        else
        {
            printCurrentTime();
            System.out.println("The breakdown of the categories is as follows: ");
            for(String category : ICMPCategoryMap.keySet())
            {
                HashMap<String, Integer> codeMap = ICMPCategoryMap.get(category);

                for(String code : codeMap.keySet())
                {
                    int count = codeMap.get(code);

                    System.out.println(category + " -> " + code + " : " + count);
                }
            }
        }
    }
}
