package tools;

import entity.ByteArray;
import entity.CrackedHash;
import javafx.application.Platform;
import main.MainController;

/*
    another copy&pasted class that just works
    do not touch it
    go to lines 32+ for actual code
 */
public class Generator {

    private MainController mainController;
    private char[] charset;
    private String attackAlgorithm;
    private long size;

    public Generator(MainController mainController, String charset, String attackAlgorithm, long size) {
        this.mainController = mainController;
        this.charset = charset.toCharArray();
        this.attackAlgorithm = attackAlgorithm;
        this.size = size;
    }

    public void generate(String str, int pos, int length)
    {
        if (length == 0) {

            // <actual code>
            // if something went wrong with this class it must be these 10 lines

            ByteArray hashedBytes = new ByteArray(Tools.hash(str, attackAlgorithm));
            if(mainController.getProject().getLoadedHashes().containsKey(hashedBytes)) {
                String hexString = mainController.getProject().getLoadedHashes().get(hashedBytes).getHexString();
                String algorithm = mainController.getProject().getLoadedHashes().get(hashedBytes).getAlgorithm();
                CrackedHash ch = new CrackedHash(hexString, algorithm, str);
                mainController.getProject().addCrackedHash(ch);
            }
            final long count = mainController.getCounter() + 1;
            mainController.setCounter(count);
            if(count%1000==0) Platform.runLater(() -> {
                mainController.updateProgressBar(count, size);
                mainController.updateCrackedHashesTableView();
            });

            // </actual code>

        } else {
            if(!mainController.isCracking()) return;
            if (pos != 0) pos = 0;
            for (int i = pos; i < charset.length; i++) generate(str + charset[i], i, length - 1);
        }
    }

}
