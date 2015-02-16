package burp;

import java.awt.Color;
import java.awt.Component;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.TransferHandler;
import javax.swing.border.BevelBorder;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {

	@Override
	/**
	 * IBurpExtenderのメソッド
	 */
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks){
		callbacks.setExtensionName("Message Copier");
		callbacks.registerMessageEditorTabFactory(this);
	}

	@Override
	/**
	 * IMessageEditorTabFactoryのメソッド
	 */
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		return new CopyTab(controller, editable);
	}

	class CopyTab implements IMessageEditorTab {

		private final IMessageEditorController controller;
		private final JPanel panel = new JPanel();
		private final JLabel label = new JLabel();

		public CopyTab(IMessageEditorController controller, boolean editable) {
			this.controller = controller;

			label.setText("Copy to File by D&D !");
			label.setBorder(new BevelBorder(BevelBorder.RAISED));
			label.setForeground(Color.BLACK);
			label.setBackground(Color.LIGHT_GRAY);
			label.setOpaque(true);

	        label.setTransferHandler(new TransferHandler() {
	            @Override public int getSourceActions(JComponent c) {
	                return COPY_OR_MOVE;
	            }
	            @Override protected Transferable createTransferable(JComponent c) {
                    return new TempFileTransferable(getRequest(), getResponse());
	            }
	        });
	        label.addMouseListener(new MouseAdapter() {
	            @Override public void mousePressed(MouseEvent e) {
//	                System.out.println(e);
	                JComponent c = (JComponent) e.getComponent();
	                c.getTransferHandler().exportAsDrag(c, e, TransferHandler.MOVE);
	            }
	        });
	        panel.add(label);
		}

	    private byte[] getRequest() {
	        return controller.getRequest();
	    }

	    private byte[] getResponse() {
	        return controller.getResponse();
	    }

		@Override
		public String getTabCaption() {
			return "Copy";
		}

		@Override
		public Component getUiComponent() {
			return panel;
		}

		@Override
		public boolean isEnabled(byte[] content, boolean isRequest) {
			return !isRequest;
		}

		@Override
		public void setMessage(byte[] content, boolean isRequest) {
		}

		@Override
		public byte[] getMessage() {
			return null;
		}

		@Override
		public boolean isModified() {
			return false;
		}

		@Override
		public byte[] getSelectedData() {
			return null;
		}
	}

	class TempFileTransferable implements Transferable {
	    private File file = null;
	    public TempFileTransferable(byte[] request, byte[] response) {
            try {
                file = File.createTempFile("burp_request_response_", ".txt");
                file.deleteOnExit();
                FileOutputStream fos = new FileOutputStream(file);
                fos.write(request);
                fos.write(new String("\r\n======================================================\r\n").getBytes());
				fos.write(response);
	            fos.close();
            } catch (FileNotFoundException e) {
            } catch (IOException ioe) {
            }
	    }
	    @Override public Object getTransferData(DataFlavor flavor) {
	        return Arrays.asList(file);
	    }
	    @Override public DataFlavor[] getTransferDataFlavors() {
	        return new DataFlavor[] {DataFlavor.javaFileListFlavor};
	    }
	    @Override public boolean isDataFlavorSupported(DataFlavor flavor) {
	        return flavor.equals(DataFlavor.javaFileListFlavor);
	    }
	}
}
