package burp;

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JMenuItem;
import javax.swing.TransferHandler;

public class BurpExtender implements IBurpExtender, IContextMenuFactory {

	@Override
	/**
	 * IBurpExtenderのメソッド
	 */
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks){
		callbacks.setExtensionName("Message Copier");
		callbacks.registerContextMenuFactory(this);
	}

	@Override
	public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
		List<JMenuItem> miList = new ArrayList<JMenuItem>();
		JMenuItem miCopy = new JMenuItem("Copy with Charset");
		switch ( invocation.getInvocationContext() ) {
		case IContextMenuInvocation.CONTEXT_PROXY_HISTORY:
			miCopy = new JMenuItem("Copy with Charset");
			miCopy.setTransferHandler(new TransferHandler() {
	            @Override public int getSourceActions(JComponent c) {
	                return COPY_OR_MOVE;
	            }
	            @Override protected Transferable createTransferable(JComponent c) {
                    return new TempFileTransferable(invocation);
	            }
	        });
			miCopy.addMouseListener(new MouseAdapter() {
	            @Override public void mousePressed(MouseEvent e) {
//	                System.out.println(e);
	                JComponent c = (JComponent) e.getComponent();
	                c.getTransferHandler().exportAsDrag(c, e, TransferHandler.COPY);
	            }
	        });
			miList.add(miCopy);
			return miList;
		case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
		case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE:
		case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
		case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
			break;
		}
		return null;
	}

	class TempFileTransferable implements Transferable {
	    private File file = null;
	    public TempFileTransferable(IContextMenuInvocation invocation) {
            try {
                file = File.createTempFile("burp_request_response_", ".txt");
                file.deleteOnExit();
                FileOutputStream fos = new FileOutputStream(file);
    			for ( int i = 0; i < messages.length; ++i ) {
    				buf.put(messages[i].getRequest());
    				buf.put(new String("\r\n======================================================\r\n").getBytes());
    				buf.put(messages[i].getResponse());
    				buf.put(new String("\r\n======================================================\r\n").getBytes());
    			}
                fos.write();
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

		private byte[] getMessages(IHttpRequestResponse[] messages) {
			long size = 0;
			for ( int i = 0; i < messages.length; ++i ) {
				size += messages[i].getRequest().length;
				size += "\r\n======================================================\r\n".length();
				size += messages[i].getResponse().length;
				size += "\r\n======================================================\r\n".length();
			}
			ByteBuffer buf = ByteBuffer.allocate(size);
			for ( int i = 0; i < messages.length; ++i ) {
				buf.put(messages[i].getRequest());
				buf.put(new String("\r\n======================================================\r\n").getBytes());
				buf.put(messages[i].getResponse());
				buf.put(new String("\r\n======================================================\r\n").getBytes());
			}
			return buf.array();
		}
	}
}
