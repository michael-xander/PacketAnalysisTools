import java.io.IOException;

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
        ProcessBuilder processBuilder = new ProcessBuilder("echo", "This is Process  Builder Example");
        try
        {
            Process process = processBuilder.start();
            int errorCode = process.waitFor();

            if(errorCode == 0)
            {
                System.out.println("No error occurred");
            }
            else
            {
                System.out.println("An error occurred");
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
