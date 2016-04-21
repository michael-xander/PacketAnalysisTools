import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;

/**
 * <h1>ICMP Categorizer</h1>
 * ICMPCategorizer utilises the tcpdump commandline tool to categorise packet data into the respective ICMP categories
 * @author Michael Kyeyune
 * @since 2016-04-21
 */
public class ICMPCategorizer
{
    public static void main(String[] args)
    {
        if(args.length == 0)
        {
            System.out.println("No arguments provided.");
            System.out.println("Please provide a file to read with -f flag e.g java ICMpCategorizer -f sample_file");
        }
        else if(args.length == 2 && args[0].equals("-f"))
        {
            String fileName = args[1];
            ProcessBuilder processBuilder = new ProcessBuilder("tcpdump" ,"-t", "icmp", "and not src net 192.168.0.0/16", "and not src net 10.0.0.0/8" ,"-r", fileName);
            try
            {
                Process process = processBuilder.start();
                int errorCode = process.waitFor();

                BufferedReader bufferedReader = null;
                String line = null;

                if(errorCode == 0)
                {
                    System.out.println("No error occurred on running command.");

                    //set up the hashmap that does the counting
                    HashMap<String, Integer> icmpCategoryMap = new HashMap<String, Integer>();

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

                        if(icmpCategoryMap.containsKey(icmpCategory))
                        {
                            //increase the count for this icmp category
                            currentCount = icmpCategoryMap.get(icmpCategory);
                            currentCount++;
                        }

                        icmpCategoryMap.put(icmpCategory, currentCount);
                    }

                    if(icmpCategoryMap.isEmpty())
                        System.out.println("No ICMP data found in file");
                    else
                    {
                        System.out.println("The tally is as follows:");

                        for (String key: icmpCategoryMap.keySet())
                        {
                            System.out.println(key + " : " + icmpCategoryMap.get(key));
                        }
                    }
                }
                else
                {
                    System.out.println("An error occurred while running command.");
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
        else
        {
            System.out.println("Incorrect arguments provided.");
            System.out.println("Please provide a file to read with -f flag e.g java ICMPCategorizer -f sample_file");
        }
    }
}
