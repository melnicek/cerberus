package tools.benchmark;

import entity.ByteArray;
import entity.CrackedHash;
import entity.LoadedHash;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.ProgressBar;
import javafx.scene.text.Text;
import tools.Tools;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;

public class BenchmarkController implements Initializable {

    @FXML private ChoiceBox<String> cbAlgorithm;
    @FXML private Button bBenchmark;
    @FXML private Text tOneThread;
    @FXML private Text tFourThread;
    @FXML private ProgressBar pbProgress;

    @Override public void initialize(URL url, ResourceBundle resourceBundle) {
        String[] algorithms = {"MD5","SHA","SHA-224","SHA-256","SHA-384","SHA-512"};
        cbAlgorithm.getItems().addAll(algorithms);
        cbAlgorithm.setValue(cbAlgorithm.getItems().get(0));
    }

    static private long oneThreadCounter = 0;
    static private boolean isBenchmarking = false;

    @FXML private void btnGenerate(){

        final String attackAlgorithm = cbAlgorithm.getValue();

        isBenchmarking =  !isBenchmarking;

        Map<ByteArray, LoadedHash> testMap = new HashMap<>();
        testMap.put(new ByteArray(new byte[]{100,100}), new LoadedHash("00",null));

        oneThreadCounter = 0;
        Thread thread = new Thread(() -> {

            long startTime = System.currentTimeMillis();

            while(true) {

                long currentTimeMillis = System.currentTimeMillis();

                if (startTime + 5000 < currentTimeMillis) stopBenchmark();
                if (!isBenchmarking) break;

                ByteArray hexString = new ByteArray(Tools.hash("benchmark", attackAlgorithm));

                if (testMap.containsKey(hexString));

                oneThreadCounter++;
                if (oneThreadCounter % 1000 == 0) Platform.runLater(() -> {
                    updateProgressBar(currentTimeMillis-startTime, 5000);
                });
            }

            String out = String.format("One thread %,d H/s", oneThreadCounter/5);
            tOneThread.setText(out);
            out = String.format("Four threads: %,d H/s", (oneThreadCounter/5)*4);
            tFourThread.setText(out);
        });
        thread.start();
    }

    private void stopBenchmark(){
        isBenchmarking = false;
    }

    private void updateProgressBar(long current, long full){
        double progress = (double) current / full;
        pbProgress.setProgress(progress);
    }

}