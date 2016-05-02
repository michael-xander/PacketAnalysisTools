package icmp;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * <h1>ICMP Filter</h1>
 * ICMPFilter utilises the tcpdump commandline tool to filter the packets to obtain only ICMP packets
 * @author Michael Kyeyune
 * @since 2016-04-24
 */
public class ICMPFilter
{
    private static final String FOLDER_ARGUMENT_INSTRUCTION = "- Provide a folder to read files from with the -d flag e.g java ICMPFilter -d sample_folder";

    public static DateFormat DATE_FORMAT = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");

    private static String DATA_SEPARATOR = "======================================================================";
    private static String ICMP_FOLDER_NAME = "icmp";
    private static String CATEGORY_FOLDER_NAME = "data";

    public static void main(String[] args)
    {
        if(args.length == 0)
        {
            System.out.println("No arguments provided. Please do one of the following:");
            System.out.println(FOLDER_ARGUMENT_INSTRUCTION);
        }
        else if (args.length == 2)
        {
            if(args[0].equals("-d"))
            {
                String folderName = args[1];

                System.out.println(DATA_SEPARATOR);
                //delete the icmp folder if already created
                File icmpFolder = new File(folderName + "/" + ICMP_FOLDER_NAME);

                if(icmpFolder.exists())
                {
                    printCurrentTime();
                    System.out.println("Deleting icmp folder in : " + folderName);
                    deleteDirectory(icmpFolder);
                }

                icmpFolder = new File(folderName + "/" + ICMP_FOLDER_NAME);

                printCurrentTime();
                if(icmpFolder.mkdir())
                {
                    System.out.println("Created icmp folder in : " + folderName);
                }
                else
                {
                    System.out.println("Failed to make icmp folder in : " + folderName);
                    System.exit(1);
                }

                File folder = new File(folderName);

                //iterate through the pcap files to filter them
                for(File file : folder.listFiles())
                {

                    if(file.isFile() && !file.isHidden())
                    {
                        System.out.println(DATA_SEPARATOR);
                        printCurrentTime();
                        System.out.println("Preparing to process file : " + file.getName());
                        generateICMPSummary(folderName, file.getName());
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

    /**
     * Utilises the tcpdump tool to filter pcap files for icmp packets and remove local traffic
     * @param folderName - the folder that contains the pcap file
     * @param fileName - the name of the pcap file
     */
    public static void generateICMPSummary(String folderName, String fileName)
    {
        ProcessBuilder processBuilder = new ProcessBuilder("tcpdump",
                "icmp and not ((src net 192.168.0.0/16 or 10.0.0.0/8) and (dst net 192.168.0.0/16 or 10.0.0.0/8))",
                "-r", folderName + "/" + fileName, "-w", folderName + "/" + ICMP_FOLDER_NAME + "/icmp_" + fileName);

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
     *
     * @param folderName
     * @param fileName
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

    /**
     * Print the current system time
     */
    public static void printCurrentTime()
    {
        System.out.print(DATE_FORMAT.format(new Date()) + " ");
    }

    /**
     * Deletes the provided file/folder
     * @param file - file or folder to delete
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
