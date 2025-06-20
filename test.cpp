#include <QWidget>
#include <QPainter>
#include <QPainterPath>
#include <QKeyEvent>
#include <QScrollArea>
#include <QScroller>
#include <QDateTime>
#include <QVBoxLayout>
#include <QApplication>
#include <QImage>
#include <QFileInfo>
#include <QRegularExpression>


class MessageViewer : public QWidget {
    Q_OBJECT

public:
    explicit MessageViewer(QWidget *parent = nullptr)
        : QWidget(parent), scrollPos(0) {
        setMinimumHeight(200);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    }

    void addMessage(const QString &message) {
        // Add timestamp and message
        QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
        messages.append(QString("[%1] %2").arg(timestamp).arg(message));
        update();
    }

    void setScrollPos(int newScrollPos) {
        scrollPos = newScrollPos;
        update();
    }

protected:
    void paintEvent(QPaintEvent *event) override {
        QPainter painter(this);
        painter.setPen(QPen(Qt::black));

        int yOffset = 0;
        int visibleMessages = height() / fontMetrics().height();  // Number of visible messages in the widget's height

        // Loop through the messages starting from the scroll position
        for (int i = scrollPos; i < messages.size(); ++i) {
            if (yOffset + fontMetrics().height() > height()) {
                break;  // Stop if the message is out of the visible area
            }

            // Draw speech bubble for each message
            QRect messageRect(10, yOffset + fontMetrics().ascent(), width() - 20, fontMetrics().height() + 10);
            QRectF bubbleRect = drawSpeechBubble(painter, messageRect);

            // Draw text inside the bubble
            painter.drawText(bubbleRect, Qt::AlignLeft | Qt::AlignTop, messages[i]);

            // Check if the message contains an image (simplified approach using regex)
            QRegularExpression imageRegex("!(.*?)(?=\\s|$)");  // Simplified image regex: !<path>
            QRegularExpressionMatch match = imageRegex.match(messages[i]);
            if (match.hasMatch()) {
                QString imagePath = match.captured(1);
                //drawImage(painter, imagePath, bubbleRect.bottomLeft());
            }

            yOffset += bubbleRect.height() + 20;  // Adjust yOffset for next message
        }
    }

    void wheelEvent(QWheelEvent *event) override {
        int delta = event->angleDelta().y() / 120;  // Normalize the wheel delta
        scrollPos = qMax(0, scrollPos + delta);  // Update the scroll position, ensuring it doesn't go below 0
        update();  // Request a repaint after scroll change
    }

    void keyPressEvent(QKeyEvent *event) override {
        if (event->key() == Qt::Key_Up) {
            scrollPos = qMax(0, scrollPos - 1);  // Scroll up with the arrow key
            update();
        } else if (event->key() == Qt::Key_Down) {
            scrollPos = qMin(messages.size() - 1, scrollPos + 1);  // Scroll down with the arrow key
            update();
        }
    }

private:
    QList<QString> messages;  // List of messages with timestamps
    int scrollPos;  // Keeps track of the current scroll position

    QRectF drawSpeechBubble(QPainter &painter, const QRect &rect) {
        // Draw speech bubble (rounded rectangle with a tail)
        QPainterPath bubblePath;
        QRectF bubbleRect = rect.adjusted(0, 0, 0, 10);  // Add padding for rounded bubble
        bubblePath.addRoundedRect(bubbleRect, 15, 15);

        // Draw the tail of the speech bubble
        QPolygon tail;
        tail << QPoint(bubbleRect.center().x() - 10, bubbleRect.bottom())
             << QPoint(bubbleRect.center().x() + 10, bubbleRect.bottom())
             << QPoint(bubbleRect.center().x(), bubbleRect.bottom() + 10);
        bubblePath.addPolygon(tail);

        // Set the bubble color and draw it
        painter.setBrush(QBrush(Qt::lightGray));
        painter.setPen(Qt::NoPen);
        painter.drawPath(bubblePath);

        return bubbleRect;
    }

    void drawImage(QPainter &painter, const QString &imagePath, const QPointF &position) {
        // Load and draw image if it's a valid path
        QImage image(imagePath);
        if (!image.isNull()) {
            int maxWidth = 100;  // Limit the width of the image
            int maxHeight = 100;  // Limit the height of the image
            image = image.scaled(maxWidth, maxHeight, Qt::KeepAspectRatio);

            // Draw the image at the specified position
            painter.drawImage(position, image);
        }
    }
};

// Simple Window to Display the Custom Widget
class MainWindow : public QWidget {
public:
    MainWindow(QWidget *parent = nullptr) : QWidget(parent) {
        QVBoxLayout *layout = new QVBoxLayout(this);

        // Create the custom MessageViewer widget
        messageViewer = new MessageViewer(this);
        
        // Create a scroll area and set the MessageViewer inside it
        QScrollArea *scrollArea = new QScrollArea(this);
        scrollArea->setWidget(messageViewer);
        scrollArea->setWidgetResizable(true);
        layout->addWidget(scrollArea);

        // Add some test messages with images (image path preceded by '!')
        messageViewer->addMessage("Message 1: Hello!");
        messageViewer->addMessage("Message 2: This is a message with an image: !path/to/image.png");
        messageViewer->addMessage("Message 3: Another message with timestamp.");
        messageViewer->addMessage("Message 4: Check this bubble!");
        messageViewer->addMessage("Message 5: No image here.");

        // Enable smooth scrolling using QScroller
        QScroller::grabGesture(scrollArea, QScroller::LeftMouseButtonGesture);
    }

protected:
    void resizeEvent(QResizeEvent *event) override {
        QWidget::resizeEvent(event);
        messageViewer->resize(event->size());  // Make sure the message viewer resizes with the window
    }

private:
    MessageViewer *messageViewer;
};

int main(int argc, char *argv[]) {
    QApplication a(argc, argv);

    MainWindow window;
    window.setWindowTitle("Custom Message Viewer with Speech Bubbles");
    window.resize(400, 300);
    window.show();

    return a.exec();
}

#include "test.moc"