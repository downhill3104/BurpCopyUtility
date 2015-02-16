package burp;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URLConnection;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JComponent;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.TransferHandler;

import org.xml.sax.InputSource;

public class BurpExtender implements IBurpExtender, IContextMenuFactory {

	private IExtensionHelpers helpers;

	@Override
	/**
	 * IBurpExtenderのメソッド
	 */
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks){
		helpers = callbacks.getHelpers();
		callbacks.setExtensionName("CopyUtility");
		callbacks.registerContextMenuFactory(this);
	}

	@Override
	public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
		List<JMenuItem> miList = new ArrayList<JMenuItem>();
		JMenuItem miCopy;
		switch ( invocation.getInvocationContext() ) {
		case IContextMenuInvocation.CONTEXT_PROXY_HISTORY:
			miCopy = new JMenuItem("Copy D&D");
			miCopy.setTransferHandler(new TransferHandler() {
	            @Override public int getSourceActions(JComponent c) {
	                return MOVE;
	            }
	            @Override protected Transferable createTransferable(JComponent c) {
                    return new TempFileTransferable(invocation);
	            }
	        });
			miCopy.addMouseListener(new MouseAdapter() {
	            @Override public void mousePressed(MouseEvent e) {
//	                System.out.println(e);
	                JComponent c = (JComponent) e.getComponent();
	                c.getTransferHandler().exportAsDrag(c, e, TransferHandler.MOVE);
	            }
	        });
			miList.add(miCopy);
			return miList;
		case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
		case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
			miCopy = new JMenuItem("Copy with Charset");
			miCopy.addActionListener(new ActionListener(){
				@Override public void actionPerformed(ActionEvent e) {
					byte[] request = invocation.getSelectedMessages()[0].getRequest();
					int[] range = invocation.getSelectionBounds();
					byte[] selection = Arrays.copyOfRange(request, range[0], range[1]);
					SetClipboard(new String(selection));
				}
			});
			miList.add(miCopy);
			return miList;
		case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE:
		case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
			miCopy = new JMenuItem("Copy with Charset");
			miCopy.addActionListener(new ActionListener(){
				@Override public void actionPerformed(ActionEvent e) {
					byte[] response = invocation.getSelectedMessages()[0].getResponse();
					int[] range = invocation.getSelectionBounds();
					byte[] selection = Arrays.copyOfRange(response, range[0], range[1]);
					Charset cs = getCharset(response);
					SetClipboard(new String(selection, cs));
					IResponseInfo responseInfo = helpers.analyzeResponse(invocation.getSelectedMessages()[0].getResponse());
					JOptionPane.showMessageDialog(null, responseInfo.getInferredMimeType() + "¥r¥n" + responseInfo.getStatedMimeType());
					ByteArrayInputStream bis = new ByteArrayInputStream(Arrays.copyOfRange(response, responseInfo.getBodyOffset(), response.length));
					try {
						String mime = URLConnection.guessContentTypeFromStream(bis);
						String encoding = new InputSource(bis).getEncoding();
						JOptionPane.showMessageDialog(null, encoding);
					} catch (IOException e1) {
						// TODO 自動生成された catch ブロック
						//e1.printStackTrace();
					}
				}
			});
			miList.add(miCopy);
			return miList;
		}
		return null;
	}

	private void SetClipboard(String str) {
		Toolkit kit = Toolkit.getDefaultToolkit();
		Clipboard clip = kit.getSystemClipboard();
		StringSelection ss = new StringSelection(str);
		clip.setContents(ss, ss);
	}

	private Charset getCharset(byte[] response) {
		IResponseInfo resInfo = helpers.analyzeResponse(response);
		List<String> headers = resInfo.getHeaders();
		for ( String header : headers ) {
			if ( header.indexOf("Content-Type: ") == 0 && header.indexOf("charset=") > 0 ) {
				Matcher m = Pattern.compile("charset=([A-Za-z0-9\\-\\+\\.:_]+)").matcher(header);
				if ( m.find() ) {
					return Charset.forName(m.group(1));
				}
			}
		}
		return Charset.forName("UTF-8");
	}

	class TempFileTransferable implements Transferable {
	    private File file = null;
	    public TempFileTransferable(IContextMenuInvocation invocation) {
            try {
                file = File.createTempFile("burp_request_response_", ".txt");
                file.deleteOnExit();
                FileOutputStream fos = new FileOutputStream(file);
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
    			for ( int i = 0; i < messages.length; ++i ) {
    				fos.write(messages[i].getRequest());
    				fos.write(new String("\r\n======================================================\r\n").getBytes());
    				fos.write(messages[i].getResponse());
    				fos.write(new String("\r\n======================================================\r\n").getBytes());
    			}
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
