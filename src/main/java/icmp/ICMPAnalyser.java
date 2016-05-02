package icmp;

import java.io.*;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Scanner;

/**
 * <h1>ICMP Analyser</h1>
 * Gets the stats for the different ICMP messages from pcap files
 * @author Michael Kyeyune
 */
public class ICMPAnalyser {

    private static final String FOLDER_ARGUMENT_INSTRUCTION = "- Provide a folder to read files from with the -d flag e.g java ICMPAnalyser -d sample_folder";
    private static String FILE_ARGUMENT_INSTRUCTION = "- Provide a pcap file to read from i.e -d file_directory -f sample_file";

    private static String TEMP_FOLDER_NAME = "icmp_temp";
    private static String SUB_TEMP_FOLDER_NAME = "data";


    private static DateFormat DATE_FORMAT = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");

    private static String DATA_DISPLAY_SEPARATOR = "======================================================================";

    public static void main(String[] args)
    {
        if(args.length == 0)
        {
            System.out.println("No arguments provided. Please do one of the following:");
            System.out.println(FOLDER_ARGUMENT_INSTRUCTION);
            System.out.println(FILE_ARGUMENT_INSTRUCTION);
        }
        else if(args.length == 2 || args.length == 4)
        {
            String folderName = args[1];
            File[] files = null;

            // directory submitted
            if(args.length == 2 && args[0].equals("-d"))
            {
                File folder = new File(folderName);
                files = folder.listFiles();
            }
            else if (args.length == 4 && args[0].equals("-d") && args[2].equals("-f")) // a file and its directory submitted
            {
                String fileName = args[3];

                File file = new File(folderName + "/" + fileName);

                File[] tempFiles = new File[1];
                tempFiles[0] = file;

                files = tempFiles;
            }
            else
            {
                System.out.println("Wrong arguments provided. Please do one of the following:");
                System.out.println(FOLDER_ARGUMENT_INSTRUCTION);
                System.out.println(FILE_ARGUMENT_INSTRUCTION);
                System.exit(1);
            }

            System.out.println(DATA_DISPLAY_SEPARATOR);

            //setup temp folder to temporary files during analysis
            File tempFolder = new File(folderName + "/" + TEMP_FOLDER_NAME);

            if(tempFolder.exists())
            {
                System.out.println(DATA_DISPLAY_SEPARATOR);
                printCurrentTime();
                System.out.println("Deleting temp folder in : " + folderName);
                deleteDirectory(tempFolder);
            }

            tempFolder = new File(folderName + "/" + TEMP_FOLDER_NAME);

            System.out.println(DATA_DISPLAY_SEPARATOR);
            printCurrentTime();

            if(tempFolder.mkdir())
            {
                System.out.println("Create temp folder in : " + folderName);
            }
            else
            {
                System.out.println("Failed to make temp folder in : " + folderName);
                System.exit(1);
            }

            //iterate through pcap files

            for(File file : files)
            {
                if(file.isFile() && !file.isHidden())
                {
                    System.out.println(DATA_DISPLAY_SEPARATOR);
                    printCurrentTime();
                    System.out.println("Preparing to process file : " + file.getName());
                    filterPcapFile(folderName, file.getName(), (folderName + "/" + TEMP_FOLDER_NAME));
                }
            }


            //start icmp category analysis on filtered files
            System.out.println(DATA_DISPLAY_SEPARATOR);
            System.out.println(DATA_DISPLAY_SEPARATOR);
            printCurrentTime();
            System.out.println("Beginning icmp message breakdown");

            files = tempFolder.listFiles();

            File subTempFolder = new File(folderName + "/" + TEMP_FOLDER_NAME + "/" + SUB_TEMP_FOLDER_NAME);
            subTempFolder.mkdir();

            //apply the ipsumdump tool to each filtered pcap to generate icmp categorization data

            for(File file : files)
            {
                if(file.isFile() && !file.isHidden())
                {
                    System.out.println(DATA_DISPLAY_SEPARATOR);
                    printCurrentTime();
                    System.out.println("Preparing anaylse ICMP messages from file : " + file.getName());
                    generateICMPStats((folderName + "/" + TEMP_FOLDER_NAME), file.getName(), (folderName + "/" + TEMP_FOLDER_NAME + "/" + SUB_TEMP_FOLDER_NAME));

                }
            }

            //read in the files with host breakdowns and tally up the counts
            System.out.println(DATA_DISPLAY_SEPARATOR);
            System.out.println(DATA_DISPLAY_SEPARATOR);
            printCurrentTime();
            System.out.println("Beginning ICMP message breakdown retrieval");

            files = subTempFolder.listFiles();

            HashMap<String, HashMap<String, Integer>> ICMPCategoryMap = new HashMap<String, HashMap<String, Integer>>();

            Scanner scanner  = null;

            for(File file : files)
            {
                if(file.isFile() && !file.isHidden())
                {
                    System.out.println(DATA_DISPLAY_SEPARATOR);
                    printCurrentTime();
                    System.out.println("Obtaining counts from file : " + file.getName());

                    try {
                        scanner = new Scanner(file);

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

                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    }
                }
            }

            // write counts to file
            String analysedDataFileName = "icmp-analysis.csv";

            FileWriter writer = null;

            System.out.println(DATA_DISPLAY_SEPARATOR);

            printCurrentTime();
            System.out.println("Writing counts to file");

            try {
                writer = new FileWriter(analysedDataFileName);
                printCurrentTime();
                System.out.println("type, code, count");

                //the column heads
                writer.append("type, code, count");
                writer.append("\n");

                for(String type : ICMPCategoryMap.keySet())
                {
                    HashMap<String, Integer> codeMap = ICMPCategoryMap.get(type);

                    for(String code : codeMap.keySet())
                    {
                        int count = codeMap.get(code);

                        System.out.println(type + ", " + code + ", " + count);
                        writer.append(type + ", " + code + ", " + count);
                        writer.append("\n");
                    }
                }

                writer.flush();
                writer.close();

            } catch (IOException e) {
                e.printStackTrace();
            }

            //delete all evidence
            deleteDirectory(tempFolder);
        }
        else
        {
            System.out.println("More arguments provided than needed. Please do one of the following:");
            System.out.println(FOLDER_ARGUMENT_INSTRUCTION);
            System.out.println(FILE_ARGUMENT_INSTRUCTION);
        }
    }

    /**
     * Filters pcap file removing local traffic and leaving only ICMP message packets using tcpdump
     * @param folderName - folder containing the pcap file
     * @param fileName - the pcap file
     * @param tempFolderName - the folder in which the filtered pcap file will be written
     */
    public static void filterPcapFile(String folderName, String fileName, String tempFolderName)
    {
        String filterString = "icmp and not ((src net 192.168.0.0/16 or 10.0.0.0/8) and (dst net 192.168.0.0/16 or 10.0.0.0/8))";

        ProcessBuilder processBuilder = new ProcessBuilder("tcpdump", filterString, "-r", (folderName + "/" + fileName),
                "-w", (tempFolderName + "/icmp_" + fileName));

        try {
            printCurrentTime();
            System.out.println("Processing file : " + fileName);

            Process process = processBuilder.start();

            int errorCode = process.waitFor();

            if(errorCode == 0)
            {
                printCurrentTime();
                System.out.println("No error occurred on running tcpdump command for file: " + fileName);
            }
            else
            {
                printCurrentTime();
                System.out.println("An error occurred while running tcpdump command for file: " + fileName);

                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
                String line = null;

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

    /**
     * Generates the icmp message type and code for the messages in the provided pcap file using the ipsumdump tool
     * @param folderName - the folder containing the pcap file
     * @param fileName - the name of the pcap file
     * @param tempFolderName - the folder in which the results file from ipsumdump will be written to
     */
    public static void generateICMPStats(String folderName, String fileName, String tempFolderName)
    {
        ProcessBuilder processBuilder = new ProcessBuilder("ipsumdump", "--icmp-type-name", "--icmp-code-name",
                "-r", (folderName + "/" + fileName), "-o", (tempFolderName + "/cat_" + fileName));

        try {
            printCurrentTime();
            System.out.println("Analysing file : " + fileName);
            Process process = processBuilder.start();

            int errorCode = process.waitFor();

            if(errorCode == 0)
            {
                printCurrentTime();
                System.out.println("No error occurred on running ipsumdump command for file: " + fileName);
            }
            else
            {
                printCurrentTime();
                System.out.println("An error occurred while running ipsumdump command for file: " + fileName);

                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
                String line = null;

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

    /**
     * Prints the current system time
     */
    public static void printCurrentTime()
    {
        System.out.print(DATE_FORMAT.format(new Date()) + " ");
    }
    /**
     * Delete file or folder
     * @param file - file or folder to be deleted
     */
    public static void deleteDirectory(File file)
    {
        if(file.isDirectory())
        {
            //if directory is empty then delete it
            if(file.list().length == 0)
            {
                file.delete();
            }
            else
            {
                for(String subFileName : file.list())
                {
                    File fileDelete = new File(file, subFileName);

                    //recursive delete
                    deleteDirectory(fileDelete);
                }

                if(file.list().length == 0)
                {
                    file.delete();
                }
            }
        }
        else
        {
            file.delete();
        }
    }
}
